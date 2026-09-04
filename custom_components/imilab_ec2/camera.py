"""Camera entities backed by the patched go2rtc.

Like the Reolink integration, this entity implements no video itself: it hands
Home Assistant an RTSP URL and the `stream` component does the rest.

The one thing that differs from a mains-powered camera, and the reason this file
is not a five-liner: **these cameras run on a 5100 mAh battery and sleep most of
the time.** Home Assistant happily asks a camera entity for still images to draw
thumbnails. Answering those by opening a stream would wake the camera every few
minutes and flatten it in days -- which is exactly why the vendor never gave
this hardware an RTSP port. So `async_camera_image` never initiates a
connection; it only ever returns a frame we already had.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

import aiohttp
from homeassistant.components.camera import Camera, CameraEntityFeature
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN, QUALITY_LABELS, STREAM_QUALITIES
from .coordinator import Ec2Coordinator, Ec2RuntimeData

_LOGGER = logging.getLogger(__name__)

SNAPSHOT_TIMEOUT = 10


@dataclass(frozen=True)
class _StreamRef:
    """Which go2rtc stream backs one camera entity."""

    name: str
    quality_suffix: str


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up one camera entity per physical camera (highest quality)."""
    data: Ec2RuntimeData = entry.runtime_data
    entities: list[Ec2Camera] = []

    for camera in data.coordinator.data.values():
        # One entity per camera, bound to the HD stream. The lower-quality
        # streams still exist in go2rtc for external players such as Kodi --
        # they just do not each need their own Home Assistant entity.
        entities.append(
            Ec2Camera(
                data, camera.slug, _StreamRef(name=camera.slug, quality_suffix="")
            )
        )

    async_add_entities(entities)


class Ec2Camera(CoordinatorEntity[Ec2Coordinator], Camera):
    """An IMILAB EC2 camera, streamed through the patched go2rtc."""

    _attr_has_entity_name = True
    _attr_name = None
    _attr_supported_features = CameraEntityFeature.STREAM

    def __init__(
        self, data: Ec2RuntimeData, camera_slug: str, stream: _StreamRef
    ) -> None:
        CoordinatorEntity.__init__(self, data.coordinator)
        Camera.__init__(self)
        self._data = data
        self._camera_slug = camera_slug
        self._stream = stream
        self._attr_unique_id = f"{camera_slug}_camera"
        self._last_image: bytes | None = None

    @property
    def _camera(self):
        return self.coordinator.data.get(self._camera_slug)

    @property
    def available(self) -> bool:
        return super().available and self._camera is not None

    @property
    def device_info(self) -> DeviceInfo:
        camera = self._camera
        return DeviceInfo(
            identifiers={(DOMAIN, self._camera_slug)},
            name=camera.name if camera else self._camera_slug,
            manufacturer="IMILAB / Xiaomi",
            model="CMSXJ11A",
            sw_version=camera.version if camera else None,
            via_device=(DOMAIN, self._data.gateway_id),
        )

    @property
    def extra_state_attributes(self) -> dict[str, str]:
        """Expose every quality's RTSP URL.

        Handy for external players and for building an IPTV playlist without
        having to know how stream names are composed.
        """
        host = self._data.lan_host
        manager = self._data.go2rtc
        return {
            f"rtsp_{QUALITY_LABELS[suffix].split()[0].lower()}": manager.rtsp_url(
                f"{self._camera_slug}{suffix}", host
            )
            for suffix in STREAM_QUALITIES
        }

    async def stream_source(self) -> str | None:
        """Hand Home Assistant the RTSP URL; `stream` does the rest.

        Cold start is roughly 16-20 s -- waking the camera plus the P2P
        handshake. That is the hardware, not a fault, so anything consuming this
        needs a generous timeout.
        """
        return self._data.go2rtc.rtsp_url(self._stream.name, "127.0.0.1")

    async def async_camera_image(
        self, width: int | None = None, height: int | None = None
    ) -> bytes | None:
        """Return a still image WITHOUT waking the camera.

        Only serves a frame if a stream is already live (someone is watching, or
        a motion event just pulled one). Otherwise it returns the last frame we
        saw, or nothing at all. Never opens a connection of its own -- see the
        module docstring.
        """
        if not await self._async_stream_is_live():
            return self._last_image

        url = (
            f"http://127.0.0.1:{self._data.go2rtc.api_listen.rsplit(':', 1)[-1]}"
            f"/api/frame.jpeg?src={self._stream.name}"
        )
        session = async_get_clientsession(self.hass)
        try:
            timeout = aiohttp.ClientTimeout(total=SNAPSHOT_TIMEOUT)
            async with session.get(url, timeout=timeout) as response:
                if response.status == 200:
                    self._last_image = await response.read()
        except (aiohttp.ClientError, TimeoutError) as err:
            _LOGGER.debug("Snapshot for %s failed: %s", self._stream.name, err)
        return self._last_image

    async def _async_stream_is_live(self) -> bool:
        """True when go2rtc already has a producer for this stream."""
        port = self._data.go2rtc.api_listen.rsplit(":", 1)[-1]
        url = f"http://127.0.0.1:{port}/api/streams?src={self._stream.name}"
        session = async_get_clientsession(self.hass)
        try:
            timeout = aiohttp.ClientTimeout(total=5)
            async with session.get(url, timeout=timeout) as response:
                if response.status != 200:
                    return False
                payload = await response.json(content_type=None)
        except (aiohttp.ClientError, TimeoutError, ValueError):
            return False
        return bool(payload.get("producers"))
