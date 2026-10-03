"""Battery, wifi and last-motion sensors for each camera.

All of it comes from the gateway (locally or relayed by the cloud) and from the
cloud's event list -- never from the camera itself, so reading it costs the
battery nothing.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from homeassistant.components.sensor import (
    SensorDeviceClass,
    SensorEntity,
    SensorEntityDescription,
    SensorStateClass,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import PERCENTAGE, EntityCategory
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.dispatcher import async_dispatcher_connect
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .camera import camera_device_info
from .const import CONF_GATEWAY_DID, DOMAIN, GATEWAY_MODEL
from .coordinator import Ec2Coordinator, Ec2RuntimeData
from .go2rtc_manager import SIGNAL_P2P
from .miio import CameraInfo


@dataclass(frozen=True, kw_only=True)
class Ec2SensorDescription(SensorEntityDescription):
    """How to read one sensor from the coordinator."""

    value: Callable[[Ec2Coordinator, CameraInfo | None], Any]
    attributes: Callable[[Ec2Coordinator, CameraInfo | None], dict[str, Any]] | None = (
        None
    )


SENSORS: tuple[Ec2SensorDescription, ...] = (
    Ec2SensorDescription(
        key="battery",
        device_class=SensorDeviceClass.BATTERY,
        native_unit_of_measurement=PERCENTAGE,
        state_class=SensorStateClass.MEASUREMENT,
        value=lambda _c, camera: camera.battery if camera else None,
        attributes=lambda _c, camera: {"charging": camera.charging} if camera else {},
    ),
    Ec2SensorDescription(
        key="wifi",
        translation_key="wifi",
        # A level the gateway reports, not dBm; its scale is not documented,
        # so it is shown as reported.
        state_class=SensorStateClass.MEASUREMENT,
        entity_category=EntityCategory.DIAGNOSTIC,
        value=lambda _c, camera: camera.wifi if camera else None,
    ),
    Ec2SensorDescription(
        key="last_motion",
        translation_key="last_motion",
        device_class=SensorDeviceClass.TIMESTAMP,
        value=lambda coordinator, _camera: coordinator.last_motion,
        attributes=lambda coordinator, _camera: {
            "event_type": (coordinator.last_event or {}).get("eventType")
        },
    ),
)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    data: Ec2RuntimeData = entry.runtime_data
    slugs = list(data.coordinator.data)
    entities: list[SensorEntity] = [
        Ec2Sensor(data, slug, description)
        for slug in slugs
        for description in SENSORS
        # The event list belongs to the gateway, not to one camera; it can be
        # pinned on a camera only when there is just one.
        if description.key != "last_motion" or len(slugs) == 1
    ]
    entities.append(
        Ec2GatewayKeySensor(data, entry.title, str(entry.data[CONF_GATEWAY_DID]))
    )
    async_add_entities(entities)


class Ec2GatewayKeySensor(SensorEntity):
    """Since when the gateway has presented its current P2P key.

    The cloud signs our client key against the gateway's key, and that
    signature keeps opening the camera -- with or without internet -- until
    the gateway rotates the key. So the age of the key is how long the
    cameras would survive an internet outage, and the history of this sensor
    is the record of how often the key changes.
    """

    _attr_has_entity_name = True
    _attr_translation_key = "p2p_key_since"
    _attr_device_class = SensorDeviceClass.TIMESTAMP
    _attr_entity_category = EntityCategory.DIAGNOSTIC
    _attr_should_poll = False

    def __init__(self, data: Ec2RuntimeData, title: str, did: str) -> None:
        self._data = data
        self._did = did
        self._attr_unique_id = f"{data.gateway_id}_p2p_key_since"
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, data.gateway_id)},
            name=f"{title} gateway",
            manufacturer="IMILAB / Xiaomi",
            model="EC2 gateway",
            model_id=GATEWAY_MODEL,
        )

    async def async_added_to_hass(self) -> None:
        @callback
        def _changed(did: str) -> None:
            if did == self._did:
                self.async_write_ha_state()

        self.async_on_remove(async_dispatcher_connect(self.hass, SIGNAL_P2P, _changed))

    @property
    def _state(self) -> dict[str, Any] | None:
        return self._data.go2rtc.p2p.get(self._did)

    @property
    def available(self) -> bool:
        # Nothing to say until the first connection shows us a key.
        return self._state is not None

    @property
    def native_value(self) -> datetime | None:
        state = self._state
        return state["since"] if state else None

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        state = self._state or {}
        return {
            "key": state.get("key"),
            "connections_with_this_key": state.get("connections"),
            "connections_without_cloud": state.get("cached_connections"),
            "key_rotations_seen": state.get("rotations"),
            "previous_key_lifetime_min_s": state.get("previous_lifetime_min"),
            "previous_key_lifetime_max_s": state.get("previous_lifetime_max"),
        }


class Ec2Sensor(CoordinatorEntity[Ec2Coordinator], SensorEntity):
    """One reading for one camera."""

    _attr_has_entity_name = True
    entity_description: Ec2SensorDescription

    def __init__(
        self, data: Ec2RuntimeData, slug: str, description: Ec2SensorDescription
    ) -> None:
        super().__init__(data.coordinator)
        self.entity_description = description
        self._data = data
        self._slug = slug
        self._attr_unique_id = f"{slug}_{description.key}"

    @property
    def _camera(self) -> CameraInfo | None:
        return self.coordinator.data.get(self._slug)

    @property
    def device_info(self) -> DeviceInfo:
        return camera_device_info(self._data, self._slug, self._camera)

    @property
    def available(self) -> bool:
        return super().available and self.native_value is not None

    @property
    def native_value(self) -> int | datetime | None:
        return self.entity_description.value(self.coordinator, self._camera)

    @property
    def extra_state_attributes(self) -> dict[str, Any] | None:
        if self.entity_description.attributes is None:
            return None
        return self.entity_description.attributes(self.coordinator, self._camera)
