"""Camera entities backed by the patched go2rtc.

Like the Reolink integration, this entity implements no video itself: it hands
Home Assistant an RTSP URL and the `stream` component does the rest.

The one thing that differs from a mains-powered camera, and the reason this file
is not a five-liner: **these cameras run on a 5100 mAh battery and sleep most of
the time.** Home Assistant asks a camera entity for still images to draw
thumbnails, every few minutes for as long as a dashboard shows it. Answering
those by opening a stream would wake the camera each time and flatten it in
days -- which is exactly why the vendor never gave this hardware an RTSP port.

So a thumbnail here is **the last frame of the last time somebody actually
watched**, kept on disk so it survives a restart. It may be two days old; that
is the point. `async_camera_image` never starts a stream. The frame is taken
while a stream is already running for a real viewer, which costs the camera
nothing extra.

A lesson learnt the hard way: go2rtc lists a producer for a stream after it
was opened once, connected or not, so "the stream has a producer" does not
mean "somebody is watching" -- a frame request on such a stream starts it.
Live means a producer with media *and* a consumer other than us.
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

import aiohttp
from homeassistant.components.camera import Camera, CameraEntityFeature
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.dispatcher import async_dispatcher_connect
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity
from homeassistant.util import dt as dt_util

from .const import DOMAIN, QUALITY_LABELS, STREAM_QUALITIES
from .coordinator import Ec2Coordinator, Ec2RuntimeData
from .go2rtc_manager import SIGNAL_DIAL
from .miio import CameraInfo

_LOGGER = logging.getLogger(__name__)

SNAPSHOT_TIMEOUT = 10
# After go2rtc dials the camera for a viewer, try to grab a frame at these
# offsets (seconds). The first ~16-20 s go on waking the camera and the P2P
# handshake, so the early attempts usually find no media yet and do nothing.
SNAPSHOT_ATTEMPTS = (8, 20, 35, 60)
# How old the kept frame must be before a running stream is asked for a new
# one. go2rtc makes a JPEG from H.264 by running ffmpeg for it, and a dashboard
# asks for thumbnails every ~10 s for as long as it is open; doing that while
# Kodi plays would load a small box like the ODROID-C2 for nothing. Once per
# five minutes is plenty for a thumbnail.
SNAPSHOT_REFRESH = 300
# How long stream_source() may hold Home Assistant while the camera wakes.
# Cold start is 16-20 s; this leaves room for a slow cloud on top.
WAKE_TIMEOUT = 35
# Home Assistant calls stream_source() once when the entity is added, to
# see which stream providers fit. That is not a viewer, and must not wake
# a battery camera; calls this soon after adding are left alone.
WAKE_GRACE = 60
# After waking the camera, the stream is held open for the viewer, at most
# this long. go2rtc drops a producer the moment its last consumer leaves,
# and redialling an awake camera still takes 5-8 s -- more than the 5 s a
# client allows -- so somebody has to stay on the line until the viewer
# arrives.
HOLD_MAX = 45


def camera_device_info(
    data: Ec2RuntimeData, slug: str, camera: CameraInfo | None
) -> DeviceInfo:
    """The camera's device, shared by its camera and sensor entities."""
    return DeviceInfo(
        identifiers={(DOMAIN, slug)},
        name=data.coordinator.name_for(slug),
        manufacturer="IMILAB / Xiaomi",
        model="EC2 camera",
        model_id="CMSXJ11A",
        sw_version=camera.version if camera else None,
        via_device=(DOMAIN, data.gateway_id),
    )


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
    snapshots = Path(hass.config.path(DOMAIN)) / "snapshots"
    entities: list[Ec2Camera] = []

    for camera in data.coordinator.data.values():
        # One entity per camera, bound to the HD stream. The lower-quality
        # streams still exist in go2rtc for external players such as Kodi --
        # they just do not each need their own Home Assistant entity.
        entities.append(
            Ec2Camera(
                data,
                camera.slug,
                _StreamRef(name=camera.slug, quality_suffix=""),
                snapshots / f"{camera.slug}.jpg",
            )
        )

    async_add_entities(entities)


class Ec2Camera(CoordinatorEntity[Ec2Coordinator], Camera):
    """An IMILAB EC2 camera, streamed through the patched go2rtc."""

    _attr_has_entity_name = True
    _attr_name = None
    _attr_supported_features = CameraEntityFeature.STREAM

    def __init__(
        self,
        data: Ec2RuntimeData,
        camera_slug: str,
        stream: _StreamRef,
        snapshot_path: Path,
    ) -> None:
        CoordinatorEntity.__init__(self, data.coordinator)
        Camera.__init__(self)
        self._data = data
        self._camera_slug = camera_slug
        self._stream = stream
        self._attr_unique_id = f"{camera_slug}_camera"
        self._snapshot_path = snapshot_path
        self._last_image: bytes | None = None
        self._last_image_at: datetime | None = None
        self._capture_task: asyncio.Task | None = None
        self._grab_lock = asyncio.Lock()
        self._added_at = 0.0
        self._hold_task: asyncio.Task | None = None

    @property
    def _camera(self):
        return self.coordinator.data.get(self._camera_slug)

    @property
    def available(self) -> bool:
        return super().available and self._camera is not None

    @property
    def device_info(self) -> DeviceInfo:
        return camera_device_info(self._data, self._camera_slug, self._camera)

    @property
    def extra_state_attributes(self) -> dict[str, str | None]:
        """Expose every quality's RTSP URL, and how old the thumbnail is.

        The URLs are handy for external players and for building an IPTV
        playlist without having to know how stream names are composed.
        """
        host = self._data.lan_host
        manager = self._data.go2rtc
        attributes: dict[str, str | None] = {
            f"rtsp_{QUALITY_LABELS[suffix].split()[0].lower()}": manager.rtsp_url(
                f"{self._camera_slug}{suffix}", host
            )
            for suffix in STREAM_QUALITIES
        }
        attributes["snapshot_at"] = (
            self._last_image_at.isoformat() if self._last_image_at else None
        )
        return attributes

    # -- lifecycle ------------------------------------------------------------

    async def async_added_to_hass(self) -> None:
        await super().async_added_to_hass()
        await self.hass.async_add_executor_job(self._load_snapshot)
        self._added_at = time.monotonic()

        @callback
        def _dialled(mac: str) -> None:
            # Somebody is opening this camera for real; grab a frame for the
            # thumbnail while it is running anyway.
            if mac.lower() != self._camera_slug or self._snapshot_is_fresh():
                return
            if self._capture_task is None or self._capture_task.done():
                self._capture_task = self.hass.async_create_task(
                    self._async_capture_while_live()
                )

        self.async_on_remove(async_dispatcher_connect(self.hass, SIGNAL_DIAL, _dialled))

    async def async_will_remove_from_hass(self) -> None:
        if self._capture_task is not None:
            self._capture_task.cancel()
        if self._hold_task is not None:
            self._hold_task.cancel()
        await super().async_will_remove_from_hass()

    def _load_snapshot(self) -> None:
        try:
            self._last_image = self._snapshot_path.read_bytes()
            self._last_image_at = dt_util.utc_from_timestamp(
                self._snapshot_path.stat().st_mtime
            )
        except OSError:
            self._last_image = None
            self._last_image_at = None

    def _store_snapshot(self, payload: bytes) -> None:
        self._snapshot_path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self._snapshot_path.with_suffix(".tmp")
        tmp.write_bytes(payload)
        tmp.replace(self._snapshot_path)

    # -- video ----------------------------------------------------------------

    async def stream_source(self) -> str | None:
        """Hand Home Assistant the RTSP URL, with the camera already awake.

        Cold start is roughly 16-20 s: waking the camera plus the P2P
        handshake. Home Assistant's own go2rtc, which carries WebRTC to the
        browser, gives an RTSP server 5 s to answer DESCRIBE, and go2rtc can
        only answer once the camera is up. So the first attempt always failed
        and the browser showed a still image; the second worked because the
        camera was awake by then. Home Assistant asks for this URL right
        before it connects, so the camera is woken here, and the URL is handed
        over once the stream carries media -- then DESCRIBE is answered at
        once.
        """
        url = self._data.go2rtc.rtsp_url(self._stream.name, "127.0.0.1")
        if self.hass.is_running and time.monotonic() - self._added_at > WAKE_GRACE:
            await self._async_wake()
        return url

    async def _async_wake(self) -> None:
        """Start the stream in go2rtc, hold it, and wait until it carries media.

        The holder is a consumer of our own (an MP4 request that reads and
        discards; no transcoding), so the producer stays up between the
        camera coming online and the viewer connecting. A plain probe was
        tried first: it returns the moment the camera is up, the producer is
        dropped with it, and the viewer's connection a second later had to
        redial -- 5-8 s even for an awake camera, still over the limit.
        """
        has_media, _ = await self._async_stream_state()
        if has_media:
            return
        if self._hold_task is None or self._hold_task.done():
            self._hold_task = self.hass.async_create_task(self._async_hold())
        started = time.monotonic()
        while time.monotonic() - started < WAKE_TIMEOUT:
            await asyncio.sleep(0.5)
            has_media, _ = await self._async_stream_state()
            if has_media:
                _LOGGER.debug(
                    "Camera %s awake in %.1f s",
                    self._stream.name,
                    time.monotonic() - started,
                )
                return
            if self._hold_task.done():
                break
        _LOGGER.warning(
            "Camera %s did not come up within %d s", self._stream.name, WAKE_TIMEOUT
        )

    async def _async_hold(self) -> None:
        """Keep the stream open until a real viewer has joined, or HOLD_MAX."""
        port = self._data.go2rtc.api_listen.rsplit(":", 1)[-1]
        url = (
            f"http://127.0.0.1:{port}/api/stream.mp4?src={self._stream.name}&video=h264"
        )
        session = async_get_clientsession(self.hass)
        started = time.monotonic()
        checked = started
        try:
            timeout = aiohttp.ClientTimeout(total=None, sock_read=WAKE_TIMEOUT)
            async with session.get(url, timeout=timeout) as response:
                if response.status != 200:
                    _LOGGER.debug(
                        "Holding %s refused: HTTP %s",
                        self._stream.name,
                        response.status,
                    )
                    return
                async for _chunk in response.content.iter_chunked(65536):
                    now = time.monotonic()
                    if now - started > HOLD_MAX:
                        break
                    if now - checked > 2:
                        checked = now
                        _, consumers = await self._async_stream_state()
                        # Ourselves plus at least one more: hand over.
                        if consumers > 1:
                            _LOGGER.debug(
                                "Viewer joined %s after %.1f s, letting go",
                                self._stream.name,
                                now - started,
                            )
                            break
        except (aiohttp.ClientError, TimeoutError) as err:
            _LOGGER.debug("Holding %s ended: %s", self._stream.name, err)

    async def async_camera_image(
        self, width: int | None = None, height: int | None = None
    ) -> bytes | None:
        """Return the last frame of the last real viewing. Never wakes the camera.

        If a viewer happens to have the stream open right now, the frame is
        refreshed from it, which costs nothing extra. Otherwise it is whatever
        was kept, however old.
        """
        if not self._snapshot_is_fresh() and await self._async_stream_is_live():
            await self._async_grab_frame()
        return self._last_image

    def _snapshot_is_fresh(self) -> bool:
        """True while the kept frame is recent enough not to bother the stream."""
        if self._last_image is None or self._last_image_at is None:
            return False
        age = (dt_util.utcnow() - self._last_image_at).total_seconds()
        return age < SNAPSHOT_REFRESH

    async def _async_capture_while_live(self) -> None:
        """Wait for a freshly dialled stream to carry media, then keep a frame."""
        started = time.monotonic()
        for offset in SNAPSHOT_ATTEMPTS:
            await asyncio.sleep(max(0.0, started + offset - time.monotonic()))
            if self._snapshot_is_fresh():
                return
            if not await self._async_stream_is_live():
                continue
            if await self._async_grab_frame():
                return

    async def _async_grab_frame(self) -> bool:
        """Fetch one frame from a stream that is already running.

        One at a time: each request has go2rtc run ffmpeg, and several
        thumbnail requests arriving together must not multiply that.
        """
        if self._grab_lock.locked():
            return False
        async with self._grab_lock:
            if self._snapshot_is_fresh():
                return True
            port = self._data.go2rtc.api_listen.rsplit(":", 1)[-1]
            url = f"http://127.0.0.1:{port}/api/frame.jpeg?src={self._stream.name}"
            session = async_get_clientsession(self.hass)
            try:
                timeout = aiohttp.ClientTimeout(total=SNAPSHOT_TIMEOUT)
                async with session.get(url, timeout=timeout) as response:
                    if response.status != 200:
                        return False
                    payload = await response.read()
            except (aiohttp.ClientError, TimeoutError) as err:
                _LOGGER.debug("Snapshot for %s failed: %s", self._stream.name, err)
                return False
            if not payload:
                return False
            self._last_image = payload
            self._last_image_at = dt_util.utcnow()
            await self.hass.async_add_executor_job(self._store_snapshot, payload)
            self.async_write_ha_state()
            return True

    async def _async_stream_is_live(self) -> bool:
        """True only when the stream carries media for somebody else.

        go2rtc keeps a producer listed after the stream was opened once, so the
        producer's existence proves nothing; it has to carry media, and a
        consumer other than us has to be attached -- or our frame request
        would be the thing that starts the stream and wakes the camera.
        """
        has_media, consumers = await self._async_stream_state()
        return has_media and consumers > 0

    async def _async_stream_state(self) -> tuple[bool, int]:
        """(producer carries media, number of consumers) for our stream."""
        port = self._data.go2rtc.api_listen.rsplit(":", 1)[-1]
        url = f"http://127.0.0.1:{port}/api/streams?src={self._stream.name}"
        session = async_get_clientsession(self.hass)
        try:
            timeout = aiohttp.ClientTimeout(total=5)
            async with session.get(url, timeout=timeout) as response:
                if response.status != 200:
                    return False, 0
                payload = await response.json(content_type=None)
        except (aiohttp.ClientError, TimeoutError, ValueError):
            return False, 0
        if not isinstance(payload, dict):
            return False, 0
        producers = payload.get("producers") or []
        has_media = any(
            isinstance(producer, dict) and producer.get("medias")
            for producer in producers
        )
        return has_media, len(payload.get("consumers") or [])
