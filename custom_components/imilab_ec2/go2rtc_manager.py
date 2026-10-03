"""Owns the patched go2rtc process.

Upstream go2rtc cannot talk to these cameras: PR #2446 adds the `mac` parameter,
the EC2 quality mapping and the `DecodeVideo` path, and it is not merged. Rather
than depend on that ever landing, this integration ships its OWN pinned build
and runs it as a subprocess -- the same approach AlexxIT's WebRTC Camera
integration takes with stock go2rtc.

Consequences, all deliberate:
  * Upstream releases cannot break us; we upgrade when we choose to.
  * No hand-built binary sitting in /addons that nobody can reproduce.
  * Works on Container/Core installs, not just HAOS where add-ons exist.

Home Assistant bundles its own *unpatched* go2rtc on 127.0.0.1:18554. Ours runs
alongside it on different ports and does not interfere.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import os
import platform
import re
import stat
from collections import deque
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs

import aiohttp
import yaml
from homeassistant.core import HomeAssistant
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.dispatcher import async_dispatcher_send
from homeassistant.util import dt as dt_util

from .const import (
    DEFAULT_API_LISTEN,
    DEFAULT_RTSP_LISTEN,
    DEFAULT_WEBRTC_LISTEN,
    DOMAIN,
    GATEWAY_MODEL,
    QUALITY_LABELS,
    STREAM_QUALITIES,
)

_LOGGER = logging.getLogger(__name__)

# Our own release, not AlexxIT's. Pinned on purpose.
RELEASE_REPO = "perseus177/ha-imilab-ec2"
BINARY_VERSION = "1.9.14-ec2.2"
DOWNLOAD_TIMEOUT = 300
# go2rtc output kept in memory for the diagnostics download and for the
# post-mortem logged when the process dies.
OUTPUT_LINES = 200
POST_MORTEM_LINES = 20
# Anything that looks like a credential is masked before a line is kept or
# logged: Xiaomi passTokens (V1:...), tokens/passwords in URLs, and the P2P
# client key and cloud signature that a dial URL carries.
_SECRET = re.compile(
    r"V1:[A-Za-z0-9+/=_-]+|((?:token|pass\w*|client_private|sign)=)[^&\s]+",
    re.IGNORECASE,
)
# Each `xiaomi: dial` line names the gateway (did) and the key it presented
# (device_public); a line about reused credentials precedes a dial that went
# without the cloud.
_DIAL = re.compile(r"xiaomi: dial xiaomi://(?:[^@\s]*@)?[^\s?]+\?(\S+)")
_REUSE = re.compile(r"reusing P2P credentials for did=(\d+)")
# Fired with the did whenever a gateway's P2P key state changes.
SIGNAL_P2P = f"{DOMAIN}_p2p_key"


def redact(line: str) -> str:
    """Mask credentials in one line of go2rtc output."""
    return _SECRET.sub(lambda m: (m.group(1) or "") + "***", line)


# Go builds are static (CGO_ENABLED=0), so one binary per arch runs on both
# glibc and the musl/Alpine that the HA core container uses.
ARCH_MAP = {
    "aarch64": "arm64",
    "arm64": "arm64",
    "x86_64": "amd64",
    "amd64": "amd64",
    "armv7l": "armv7",
}

RESTART_BACKOFF = (1, 2, 5, 10, 30, 60)


def _human(seconds: float) -> str:
    """Seconds as `1d 2h 03m` for the log."""
    total = int(seconds)
    days, rest = divmod(total, 86400)
    hours, rest = divmod(rest, 3600)
    minutes = rest // 60
    if days:
        return f"{days}d {hours}h {minutes:02d}m"
    if hours:
        return f"{hours}h {minutes:02d}m"
    return f"{minutes}m {rest % 60:02d}s"


class Go2rtcError(Exception):
    """Raised when the streaming backend cannot be prepared or started."""


@dataclass(frozen=True)
class StreamSpec:
    """One go2rtc stream: a camera at one quality."""

    name: str
    label: str
    url: str


def build_streams(
    user_id: str, gateway_host: str, gateway_did: int, cameras: list
) -> list[StreamSpec]:
    """Build the go2rtc stream list for every camera at every quality.

    Stream names are `<slug>`, `<slug>_fluent`, `<slug>_low`. They are stable
    and externally visible: an M3U playlist consumed by Kodi points straight at
    them, so renaming a stream breaks somebody's TV. Treat these as an API.
    """
    streams: list[StreamSpec] = []
    for camera in cameras:
        for suffix, subtype in STREAM_QUALITIES.items():
            streams.append(
                StreamSpec(
                    name=f"{camera.slug}{suffix}",
                    label=f"{camera.name} {QUALITY_LABELS[suffix]}".strip(),
                    url=(
                        f"xiaomi://{user_id}:@{gateway_host}"
                        f"?did={gateway_did}"
                        f"&model={GATEWAY_MODEL}"
                        f"&mac={camera.mac}"
                        f"&subtype={subtype}"
                    ),
                )
            )
    return streams


class Go2rtcManager:
    """Downloads, configures and supervises the patched go2rtc binary."""

    def __init__(self, hass: HomeAssistant, base_dir: Path) -> None:
        self._hass = hass
        self._base_dir = base_dir
        self._process: asyncio.subprocess.Process | None = None
        self._supervisor: asyncio.Task | None = None
        self._stopping = False
        self._lock = asyncio.Lock()
        # Called when go2rtc reports the cloud refused it. Set by the entry
        # setup so a rotated token can be renewed without user involvement.
        self.on_auth_failure: Callable[[], Awaitable[None]] | None = None
        self.api_listen = DEFAULT_API_LISTEN
        self.rtsp_listen = DEFAULT_RTSP_LISTEN
        self.webrtc_listen = DEFAULT_WEBRTC_LISTEN
        self.output: deque[str] = deque(maxlen=OUTPUT_LINES)
        self.restarts = 0
        self.last_exit_code: int | None = None
        # Per gateway did: the P2P key it currently presents and how long it
        # has, so the key's lifetime can be read off the log and a sensor.
        # The cloud signs our client key against this device key, and the
        # signature stays usable until the key changes -- which is how long
        # the cameras survive without internet.
        self.p2p: dict[str, dict[str, Any]] = {}
        self._reuse_pending: set[str] = set()

    @property
    def pid(self) -> int | None:
        """The running process, or None."""
        process = self._process
        if process is None or process.returncode is not None:
            return None
        return process.pid

    # -- paths ----------------------------------------------------------------

    @property
    def binary_path(self) -> Path:
        return self._base_dir / f"go2rtc-{BINARY_VERSION}-{self._arch()}"

    @property
    def config_path(self) -> Path:
        return self._base_dir / "go2rtc.yaml"

    @staticmethod
    def _arch() -> str:
        machine = platform.machine().lower()
        if machine not in ARCH_MAP:
            raise Go2rtcError(f"unsupported architecture: {machine}")
        return ARCH_MAP[machine]

    def rtsp_url(self, stream: str, host: str) -> str:
        """RTSP URL for a stream, as seen from `host`."""
        port = self.rtsp_listen.rsplit(":", 1)[-1] or "8554"
        return f"rtsp://{host}:{port}/{stream}"

    # -- binary ---------------------------------------------------------------

    async def async_ensure_binary(self) -> None:
        """Download the pinned binary if it is not already on disk.

        The download is checked against the `.sha256` published alongside it.
        This is an executable we are about to run, so a mismatch is fatal --
        never fall back to running it anyway.
        """
        if await self._hass.async_add_executor_job(self.binary_path.is_file):
            return

        arch = self._arch()
        base = (
            f"https://github.com/{RELEASE_REPO}/releases/download/"
            f"go2rtc-{BINARY_VERSION}/go2rtc-{arch}"
        )
        _LOGGER.info("Downloading go2rtc %s (%s)", BINARY_VERSION, arch)

        payload = await self._async_fetch(base)
        expected = await self._async_expected_digest(f"{base}.sha256")
        actual = hashlib.sha256(payload).hexdigest()
        if actual != expected:
            raise Go2rtcError(
                f"checksum mismatch for go2rtc-{arch}: "
                f"expected {expected}, got {actual}"
            )

        await self._hass.async_add_executor_job(
            self._write_binary,
            self.binary_path.with_suffix(".part"),
            self.binary_path,
            payload,
        )
        _LOGGER.info(
            "go2rtc %s installed (%d bytes, sha256 verified)",
            BINARY_VERSION,
            len(payload),
        )

    async def _async_fetch(self, url: str) -> bytes:
        session = async_get_clientsession(self._hass)
        try:
            timeout = aiohttp.ClientTimeout(total=DOWNLOAD_TIMEOUT)
            async with session.get(url, timeout=timeout) as response:
                if response.status != 200:
                    raise Go2rtcError(
                        f"download failed: HTTP {response.status} for {url}"
                    )
                return await response.read()
        except aiohttp.ClientError as err:
            raise Go2rtcError(f"download failed: {err}") from err

    async def _async_expected_digest(self, url: str) -> str:
        """Read the published `sha256sum` line and return just the digest."""
        raw = await self._async_fetch(url)
        text = raw.decode("utf-8", "replace").strip()
        digest = text.split()[0] if text else ""
        if len(digest) != 64:
            raise Go2rtcError(f"unusable checksum file at {url}")
        return digest.lower()

    def _write_binary(self, tmp_path: Path, final_path: Path, payload: bytes) -> None:
        """Write then rename, so a half-download never looks installed."""
        final_path.parent.mkdir(parents=True, exist_ok=True)
        tmp_path.write_bytes(payload)
        tmp_path.chmod(tmp_path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP)
        os.replace(tmp_path, final_path)

    # -- config ---------------------------------------------------------------

    async def async_write_config(
        self, accounts: dict[str, str], streams: list[StreamSpec]
    ) -> None:
        """Render go2rtc.yaml from the entries we manage."""
        config = {
            "api": {"listen": self.api_listen},
            "rtsp": {"listen": self.rtsp_listen},
            "webrtc": {"listen": self.webrtc_listen},
            # `debug` logs the dial URL, which is useful. `trace` would also log
            # the devices' miio tokens -- never default to it.
            "log": {"level": "info", "xiaomi": "debug"},
            "xiaomi": accounts,
            "streams": {spec.name: spec.url for spec in streams},
        }
        await self._hass.async_add_executor_job(self._dump_config, config)

    def _dump_config(self, config: dict) -> None:
        self.config_path.parent.mkdir(parents=True, exist_ok=True)
        # The file holds the account passToken, so keep it owner-readable only.
        self.config_path.write_text(
            yaml.safe_dump(config, sort_keys=False, allow_unicode=True),
            encoding="utf-8",
        )
        self.config_path.chmod(0o600)

    # -- process --------------------------------------------------------------

    async def async_start(self) -> None:
        """Start go2rtc and keep it running."""
        async with self._lock:
            if self._process is not None and self._process.returncode is None:
                return
            self._stopping = False
            await self._async_spawn()
            if self._supervisor is None or self._supervisor.done():
                self._supervisor = self._hass.async_create_background_task(
                    self._async_supervise(), "imilab_ec2_go2rtc_supervisor"
                )

    async def _async_spawn(self) -> None:
        try:
            self._process = await asyncio.create_subprocess_exec(
                str(self.binary_path),
                "-config",
                str(self.config_path),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
            )
        except OSError as err:
            # The most likely cause is /config mounted noexec. Say so, because
            # the raw errno sends people looking in the wrong place.
            raise Go2rtcError(
                f"cannot execute {self.binary_path}: {err}. "
                "If this is a permission error, check that the config directory "
                "is not mounted noexec."
            ) from err
        _LOGGER.info("go2rtc started (pid %s)", self._process.pid)

    async def _async_supervise(self) -> None:
        """Restart go2rtc if it dies, with backoff, until we ask it to stop."""
        attempt = 0
        while not self._stopping:
            process = self._process
            if process is None:
                return
            await self._async_drain(process)
            code = await process.wait()
            if self._stopping:
                return
            delay = RESTART_BACKOFF[min(attempt, len(RESTART_BACKOFF) - 1)]
            self.last_exit_code = code
            self.restarts += 1
            _LOGGER.warning(
                "go2rtc exited with code %s, restarting in %ss. Its last output:\n%s",
                code,
                delay,
                "\n".join(list(self.output)[-POST_MORTEM_LINES:]) or "(none)",
            )
            await asyncio.sleep(delay)
            attempt += 1
            try:
                await self._async_spawn()
            except Go2rtcError as err:
                _LOGGER.error("go2rtc restart failed: %s", err)
                return

    async def _async_drain(self, process: asyncio.subprocess.Process) -> None:
        """Forward go2rtc output into the HA log, watching for a dead token.

        go2rtc fetches P2P keys from the cloud on every single connection, so a
        rotated account token shows up here as `401 Unauthorized` the instant
        somebody opens a camera. That is the earliest signal available, and it
        is what lets the token be renewed before anyone reports "the cameras
        stopped working".
        """
        if process.stdout is None:
            return
        async for raw in process.stdout:
            raw_line = raw.decode("utf-8", "replace").rstrip()
            if not raw_line:
                continue
            self._track_p2p(raw_line)
            line = redact(raw_line)
            self.output.append(line)
            if "401" in line and "nauthorized" in line:
                _LOGGER.warning("go2rtc: Xiaomi cloud refused the account: %s", line)
                if self.on_auth_failure is not None:
                    self._hass.async_create_task(self.on_auth_failure())
            elif " ERR " in line or " WRN " in line or "error" in line:
                # WRN carries the stream failures (EOF, timeouts) that explain
                # "the camera did not open"; at debug they were invisible.
                _LOGGER.warning("go2rtc: %s", line)
            else:
                _LOGGER.debug("go2rtc: %s", line)

    def _track_p2p(self, line: str) -> None:
        """Follow each gateway's P2P key across dials.

        A key change is only ever noticed at the next connection, so the
        previous key's lifetime is known as a range: at least until it was
        last seen, at most until the new one appeared.
        """
        if match := _REUSE.search(line):
            self._reuse_pending.add(match.group(1))
            return
        match = _DIAL.search(line)
        if match is None:
            return
        query = parse_qs(match.group(1))
        did = (query.get("did") or [""])[0]
        key = (query.get("device_public") or [""])[0]
        if not did or not key:
            return

        now = dt_util.utcnow()
        cached = did in self._reuse_pending
        self._reuse_pending.discard(did)
        fingerprint = key[:12]
        state = self.p2p.get(did)

        if state is None:
            _LOGGER.info("Gateway %s: P2P key %s first seen", did, fingerprint)
            state = {
                "key": fingerprint,
                "since": now,
                "connections": 0,
                "cached_connections": 0,
                "rotations": 0,
                "previous_lifetime_min": None,
                "previous_lifetime_max": None,
            }
        elif state["key"] != fingerprint:
            at_least = (state["last_seen"] - state["since"]).total_seconds()
            at_most = (now - state["since"]).total_seconds()
            _LOGGER.info(
                "Gateway %s: P2P key rotated to %s. The previous key %s was in "
                "use for between %s and %s, over %d connection(s)",
                did,
                fingerprint,
                state["key"],
                _human(at_least),
                _human(at_most),
                state["connections"],
            )
            state = {
                "key": fingerprint,
                "since": now,
                "connections": 0,
                "cached_connections": 0,
                "rotations": state["rotations"] + 1,
                "previous_lifetime_min": at_least,
                "previous_lifetime_max": at_most,
            }

        state["last_seen"] = now
        state["connections"] += 1
        if cached:
            state["cached_connections"] += 1
        self.p2p[did] = state
        async_dispatcher_send(self._hass, SIGNAL_P2P, did)

    async def async_stop(self) -> None:
        """Stop go2rtc and its supervisor."""
        self._stopping = True
        if self._supervisor is not None:
            self._supervisor.cancel()
            self._supervisor = None
        process = self._process
        self._process = None
        if process is None or process.returncode is not None:
            return
        process.terminate()
        try:
            await asyncio.wait_for(process.wait(), timeout=10)
        except TimeoutError:
            _LOGGER.warning("go2rtc did not exit, killing it")
            process.kill()
            await process.wait()
