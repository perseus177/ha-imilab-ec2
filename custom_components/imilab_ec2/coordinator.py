"""Polling coordinator for the EC2 gateway.

Runs in one of two modes:

  * **Live** -- a valid gateway miio token, so `get_camera_list` is polled and
    battery/motion/wifi state is real. Polling is free as far as the cameras are
    concerned: the gateway is mains powered and answers from its own state, so
    nothing here ever wakes a camera.
  * **Static** -- no usable token. The camera list comes from the config entry
    and never changes. Streaming does not need the token, so this mode still
    gives full video; only the sensors are missing.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import timedelta
from typing import Any

from homeassistant.core import HomeAssistant
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from .const import DOMAIN, FAST_INTERVAL
from .go2rtc_manager import Go2rtcManager
from .miio import CameraInfo, MiioError, MiioGateway

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


class Ec2Coordinator(DataUpdateCoordinator[dict[str, CameraInfo]]):
    """Keeps the camera list (and, when possible, its state) up to date."""

    def __init__(
        self,
        hass: HomeAssistant,
        host: str,
        gateway: MiioGateway | None,
        fallback: list[CameraInfo],
    ) -> None:
        super().__init__(
            hass,
            _LOGGER,
            name=f"{DOMAIN} {host}",
            # No token means nothing to poll for; do not wake up on a timer
            # just to re-report the same static list.
            update_interval=timedelta(seconds=FAST_INTERVAL) if gateway else None,
        )
        self._gateway = gateway
        self._fallback = {camera.slug: camera for camera in fallback}
        self._warned = False

    @property
    def live(self) -> bool:
        """True when we are really talking to the gateway."""
        return self._gateway is not None

    async def _async_update_data(self) -> dict[str, CameraInfo]:
        if self._gateway is None:
            return self._fallback

        try:
            cameras = await self.hass.async_add_executor_job(self._gateway.camera_list)
        except MiioError as err:
            if self._fallback:
                # Streaming does not depend on this call, so degrade to the
                # known camera list instead of taking the whole entry down.
                if not self._warned:
                    _LOGGER.warning(
                        "Gateway stopped answering get_camera_list (%s); "
                        "keeping the configured cameras and continuing without "
                        "sensor state. A rotated miio token is the usual cause",
                        err,
                    )
                    self._warned = True
                return self._fallback
            raise UpdateFailed(str(err)) from err

        self._warned = False
        return {camera.slug: camera for camera in cameras}
