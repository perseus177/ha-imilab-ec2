"""Polling coordinator for the EC2 gateway.

The camera list and its state (battery, wifi, motion) come from the gateway's
`get_camera_list`, read from the first source that works:

  * **Local** -- a valid gateway miio token, polled on the LAN every 15 s.
    Free as far as the cameras are concerned: the gateway is mains powered and
    answers from its own state, so nothing here ever wakes a camera.
  * **Cloud** -- the same call relayed by the Xiaomi cloud, once a minute. Some
    gateways reject their local token, even one the cloud just issued; the
    cloud path needs only the account. The LAN is retried every half hour.
  * **Static** -- neither works. The camera list comes from the config entry;
    streaming still works, only the sensors are missing.

The last motion event comes from the cloud's camera event list, which is the
only place that records when it happened.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from homeassistant.core import HomeAssistant
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from .const import (
    CLOUD_INTERVAL,
    DOMAIN,
    EVENT_LOOKBACK_DAYS,
    FAST_INTERVAL,
    GATEWAY_MODEL,
    LOCAL_RETRY_INTERVAL,
)
from .go2rtc_manager import Go2rtcManager
from .miio import CameraInfo, MiioError, MiioGateway
from .xiaomi_cloud import XiaomiCloud, XiaomiCloudError

_LOGGER = logging.getLogger(__name__)


@dataclass
class Ec2RuntimeData:
    """Everything the platforms need, hung off the config entry."""

    coordinator: Ec2Coordinator
    go2rtc: Go2rtcManager
    gateway_id: str
    lan_host: str
    # Set during setup; keeps the Xiaomi session alive on its own.
    renewer: Any = None


def static_camera(mac: str, name: str) -> CameraInfo:
    """A camera we know exists but cannot query."""
    return CameraInfo(
        mac=mac.upper(),
        name=name,
        battery=None,
        battery_status=None,
        charging=False,
        wifi=None,
        pir=None,
        night=False,
        event=None,
        version=None,
    )


def _is_factory_name(name: str) -> bool:
    """True for the gateway's built-in camera name rather than a person's.

    Every camera reports the same Chinese factory name, 小白智能摄像机电池版
    ("Xiaobai smart camera, battery edition"), which tells nobody which camera
    it is.
    """
    return not name or any("一" <= char <= "鿿" for char in name)


def camera_names(cameras: list[CameraInfo], gateway_name: str) -> dict[str, str]:
    """A readable name per camera slug.

    A name somebody chose is kept. The factory name is replaced with the
    gateway's own -- which is what people name in the Mi Home app ("Balcony")
    -- plus "camera", numbered when one gateway serves several.
    """
    unnamed = [camera for camera in cameras if _is_factory_name(camera.name)]
    names: dict[str, str] = {}
    for camera in cameras:
        if not _is_factory_name(camera.name):
            names[camera.slug] = camera.name
        elif len(unnamed) == 1:
            names[camera.slug] = f"{gateway_name} camera"
        else:
            names[camera.slug] = f"{gateway_name} camera {unnamed.index(camera) + 1}"
    return names


class CloudSource:
    """The gateway's state through the Xiaomi cloud, signed in on demand."""

    def __init__(
        self,
        cloud_factory: Callable[[], XiaomiCloud],
        credentials: Callable[[], tuple[str, str]],
        country: str,
        did: str,
    ) -> None:
        self._factory = cloud_factory
        self._credentials = credentials
        self.country = country
        self.did = did
        self._cloud: XiaomiCloud | None = None

    async def _async_call(self, func):
        """Run `func(cloud)`, signing in first and once more if it is refused."""
        for attempt in range(2):
            if self._cloud is None:
                cloud = self._factory()
                user_id, pass_token = self._credentials()
                await cloud.async_login_with_token(user_id, pass_token)
                self._cloud = cloud
            try:
                return await func(self._cloud)
            except XiaomiCloudError:
                # A stale session looks like any other refusal; start over
                # once with a fresh sign-in before believing it.
                self._cloud = None
                if attempt:
                    raise
        return None

    async def async_camera_list(self) -> list[CameraInfo]:
        result = await self._async_call(
            lambda cloud: cloud.async_device_rpc(
                self.country, self.did, "get_camera_list"
            )
        )
        cameras = [
            CameraInfo.from_dict(item)
            for item in (result if isinstance(result, list) else [])
            if isinstance(item, dict) and item.get("mac")
        ]
        if not cameras:
            raise XiaomiCloudError(f"get_camera_list via cloud returned {result!r}")
        return cameras

    async def async_last_event(self) -> tuple[dict[str, Any] | None, Any]:
        since = int((time.time() - EVENT_LOOKBACK_DAYS * 86400) * 1000)
        return await self._async_call(
            lambda cloud: cloud.async_last_event(
                self.country, self.did, GATEWAY_MODEL, since
            )
        )


class Ec2Coordinator(DataUpdateCoordinator[dict[str, CameraInfo]]):
    """Keeps the camera list, and whatever state can be had, up to date."""

    def __init__(
        self,
        hass: HomeAssistant,
        host: str,
        gateway: MiioGateway | None,
        fallback: list[CameraInfo],
        gateway_did: str | None = None,
        cloud: CloudSource | None = None,
        gateway_name: str = "EC2",
    ) -> None:
        super().__init__(
            hass,
            _LOGGER,
            name=f"{DOMAIN} {host}",
            update_interval=timedelta(seconds=FAST_INTERVAL)
            if gateway
            else timedelta(seconds=CLOUD_INTERVAL)
            if cloud
            else None,
        )
        self._gateway = gateway
        self._cloud = cloud
        self._fallback = {camera.slug: camera for camera in fallback}
        self._gateway_did = gateway_did
        self.gateway_name = gateway_name
        self._local_retry_at = 0.0
        self._warned_local = False
        self._warned_cloud = False
        self._warned_event = False
        # Where the data came from last time: "local", "cloud" or "static".
        self.source = "static"
        self.names: dict[str, str] = camera_names(fallback, gateway_name)
        self.last_motion: datetime | None = None
        self.last_event: dict[str, Any] | None = None
        # Kept for the diagnostics download.
        self.last_error: str | None = None
        self.diagnosis: str | None = None
        self.cloud_error: str | None = None
        self.event_reply: Any = None

    @property
    def live(self) -> bool:
        """True when the state is real rather than a configured list."""
        return self.source != "static"

    def name_for(self, slug: str) -> str:
        return self.names.get(slug, slug)

    async def _async_update_data(self) -> dict[str, CameraInfo]:
        cameras = await self._async_local()
        if cameras is None:
            cameras = await self._async_cloud_list()
        if cameras is None:
            if not self._fallback:
                raise UpdateFailed(
                    "The gateway did not list its cameras, locally "
                    f"({self.diagnosis or self.last_error or 'no token'}) or "
                    f"through the cloud ({self.cloud_error or 'not available'}), "
                    "and none are configured; enter their MACs with Reconfigure"
                )
            self.source = "static"
            cameras = list(self._fallback.values())

        # Only cameras the entry knows about get entities, but their state may
        # come from any source. Keep names stable across sources.
        found = {camera.slug: camera for camera in cameras}
        if self._fallback:
            found = {
                slug: found.get(slug, camera) for slug, camera in self._fallback.items()
            }
        self.names = camera_names(list(found.values()), self.gateway_name)

        if self._cloud is not None:
            await self._async_last_motion()

        if self._gateway is not None or self._cloud is not None:
            self.update_interval = timedelta(
                seconds=FAST_INTERVAL if self.source == "local" else CLOUD_INTERVAL
            )
        return found

    async def _async_local(self) -> list[CameraInfo] | None:
        if self._gateway is None or time.monotonic() < self._local_retry_at:
            return None
        try:
            cameras = await self.hass.async_add_executor_job(self._gateway.camera_list)
        except MiioError as err:
            self.last_error = str(err)
            self._local_retry_at = time.monotonic() + LOCAL_RETRY_INTERVAL
            if not self._warned_local:
                # Once per outage: a few extra packets to find out WHY, so the
                # log says more than "no response".
                self.diagnosis = await self.hass.async_add_executor_job(
                    self._gateway.diagnose, self._gateway_did
                )
                _LOGGER.warning(
                    "Gateway did not answer get_camera_list on the LAN (%s); "
                    "using the cloud instead and trying the LAN again in %d min. "
                    "Diagnosis: %s",
                    err,
                    LOCAL_RETRY_INTERVAL // 60,
                    self.diagnosis,
                )
                self._warned_local = True
            return None
        if self._warned_local:
            _LOGGER.info("Gateway answers get_camera_list on the LAN again")
        self._warned_local = False
        self.last_error = self.diagnosis = None
        self.source = "local"
        return cameras

    async def _async_cloud_list(self) -> list[CameraInfo] | None:
        if self._cloud is None:
            return None
        try:
            cameras = await self._cloud.async_camera_list()
        except XiaomiCloudError as err:
            self.cloud_error = str(err)
            if not self._warned_cloud:
                _LOGGER.warning(
                    "The cloud could not list the gateway's cameras either: %s; "
                    "sensors stay unavailable",
                    err,
                )
                self._warned_cloud = True
            return None
        if self._warned_cloud:
            _LOGGER.info("The cloud lists the gateway's cameras again")
        self._warned_cloud = False
        self.cloud_error = None
        self.source = "cloud"
        return cameras

    async def _async_last_motion(self) -> None:
        assert self._cloud is not None
        try:
            event, reply = await self._cloud.async_last_event()
        except XiaomiCloudError as err:
            self.event_reply = str(err)
            if not self._warned_event:
                _LOGGER.warning("Could not read the camera event list: %s", err)
                self._warned_event = True
            return
        self.event_reply = reply
        if event is None:
            if not self._warned_event:
                # Not necessarily wrong -- there may simply have been no event
                # -- but this path is new, so show what the cloud said.
                _LOGGER.warning(
                    "The cloud reports no camera events in the last %d days "
                    "(reply: %s)",
                    EVENT_LOOKBACK_DAYS,
                    str(reply)[:500],
                )
                self._warned_event = True
            return
        self._warned_event = False
        created = event.get("createTime")
        try:
            moment = datetime.fromtimestamp(int(created) / 1000, tz=UTC)
        except (TypeError, ValueError):
            _LOGGER.warning("Camera event without a usable time: %s", event)
            return
        if self.last_motion is None:
            _LOGGER.info(
                "Last camera event: %s (%s)", moment.isoformat(), event.get("eventType")
            )
        self.last_motion = moment
        self.last_event = {
            key: event.get(key) for key in ("eventType", "createTime", "fileId")
        }
