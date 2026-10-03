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
from homeassistant.core import HomeAssistant
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .camera import camera_device_info
from .coordinator import Ec2Coordinator, Ec2RuntimeData
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
    entities = [
        Ec2Sensor(data, slug, description)
        for slug in slugs
        for description in SENSORS
        # The event list belongs to the gateway, not to one camera; it can be
        # pinned on a camera only when there is just one.
        if description.key != "last_motion" or len(slugs) == 1
    ]
    async_add_entities(entities)


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
