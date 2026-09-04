"""Minimal local miio client for the EC2 gateway.

Only the read paths we need. The gateway answers `get_camera_list` with the
full state of every camera it serves -- MAC, battery, PIR, motion, wifi, night
mode -- without waking the camera. The gateway is mains powered, so polling it
costs the camera's battery nothing.

Deliberately dependency-free beyond `cryptography`, which Home Assistant
already ships (verified 48.0.0 in the core container).
"""

from __future__ import annotations

import hashlib
import json
import logging
import socket
import struct
import time
from dataclasses import dataclass
from typing import Any

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

_LOGGER = logging.getLogger(__name__)

MIIO_PORT = 54321
TIMEOUT = 6.0
# The gateway silently drops requests often enough that one timeout proves
# nothing. Measured: a retry almost always succeeds.
ATTEMPTS = 3

# Methods the gateway does NOT implement -- it simply never answers, so a probe
# costs a full timeout. Recorded here so nobody re-discovers them the hard way:
# get_camera_prop, get_prop, get_device_prop, get_properties, get_device_list,
# get_ipc_list, get_sub_device_list, get_camera_info, get_hub_info.


class MiioError(Exception):
    """Raised when the gateway cannot be reached or refuses a call."""


@dataclass(frozen=True)
class CameraInfo:
    """One camera as reported by the gateway."""

    mac: str
    name: str
    battery: int | None
    battery_status: int | None
    charging: bool
    wifi: int | None
    pir: int | None
    night: bool
    event: str | None
    version: str | None

    @property
    def slug(self) -> str:
        """Stable, lowercase id derived from the MAC."""
        return self.mac.lower()

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> CameraInfo:
        """Build from one `get_camera_list` entry."""
        return cls(
            mac=str(raw.get("mac", "")).upper(),
            name=str(raw.get("name", "")) or "EC2 camera",
            battery=_as_int(raw.get("battery")),
            battery_status=_as_int(raw.get("battery_status")),
            # `power` is the mains/charging flag on this firmware.
            charging=bool(raw.get("power")),
            wifi=_as_int(raw.get("wifi")),
            # NOTE: the meaning of `pir` is not established. Observed 0 on one
            # camera and 2 on another. Exposed raw rather than guessed at.
            pir=_as_int(raw.get("pir")),
            night=bool(raw.get("night")),
            # NOTE: unknown whether `event` is a live state or a latch of the
            # last event. Until that is settled, do not build a motion trigger
            # on it -- see the integration README.
            event=raw.get("event"),
            version=raw.get("version"),
        )


def _as_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


class MiioGateway:
    """Blocking miio client. Call from an executor, never from the event loop."""

    def __init__(self, host: str, token: str) -> None:
        self._host = host
        self._token = bytes.fromhex(token)
        self._key = hashlib.md5(self._token).digest()  # noqa: S324 - miio spec
        self._iv = hashlib.md5(self._key + self._token).digest()  # noqa: S324
        self._msg_id = 100

    # -- crypto ---------------------------------------------------------------

    def _encrypt(self, data: bytes) -> bytes:
        pad = 16 - len(data) % 16
        data += bytes([pad]) * pad
        enc = Cipher(algorithms.AES(self._key), modes.CBC(self._iv)).encryptor()
        return enc.update(data) + enc.finalize()

    def _decrypt(self, data: bytes) -> bytes:
        if not data:
            return b""
        dec = Cipher(algorithms.AES(self._key), modes.CBC(self._iv)).decryptor()
        out = dec.update(data) + dec.finalize()
        if out and 1 <= out[-1] <= 16:
            out = out[: -out[-1]]
        return out

    def _packet(self, did: int, stamp: int, payload: bytes) -> bytes:
        enc = self._encrypt(payload) if payload else b""
        header = struct.pack(">HHII", 0x2131, 32 + len(enc), 0, did) + struct.pack(
            ">I", stamp
        )
        checksum = hashlib.md5(header + self._token + enc).digest()  # noqa: S324
        return header + checksum + enc

    # -- transport ------------------------------------------------------------

    def _handshake(self, sock: socket.socket) -> tuple[int, int]:
        """Return (did, stamp).

        The handshake hands us the device id for free, which is why the config
        flow does not need to ask the user for a `did`.
        """
        sock.sendto(b"\x21\x31\x00\x20" + b"\xff" * 28, (self._host, MIIO_PORT))
        data, _ = sock.recvfrom(4096)
        if len(data) < 16:
            raise MiioError("short handshake response")
        did, stamp = struct.unpack(">II", data[8:16])
        return did, stamp

    def _call(self, method: str, params: list[Any] | None = None) -> Any:
        """Run one miio call and return the decoded `result`.

        This gateway drops requests fairly often, so a single timeout means
        nothing -- retry before believing it. It also emits duplicate handshake
        replies, which arrive as bodyless 32-byte packets; reading one of those
        as if it were the answer yields an empty payload, so they are skipped
        rather than parsed.
        """
        self._msg_id += 1
        last_error: str = "no response"

        for attempt in range(ATTEMPTS):
            try:
                data = self._exchange(method, params)
            except MiioError as err:
                last_error = str(err)
                continue

            try:
                decoded = json.loads(
                    self._decrypt(data[32:]).decode("utf-8", "replace")
                )
            except (ValueError, UnicodeDecodeError):
                last_error = "undecodable response"
                _LOGGER.debug(
                    "%s: attempt %d returned %d undecodable bytes",
                    method,
                    attempt + 1,
                    len(data) - 32,
                )
                continue

            if "error" in decoded:
                raise MiioError(f"{method}: {decoded['error']}")
            return decoded.get("result")

        raise MiioError(f"{method}: {last_error} from {self._host}")

    def _exchange(self, method: str, params: list[Any] | None) -> bytes:
        """One handshake-and-ask round trip; returns the raw reply packet."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(TIMEOUT)
        try:
            did, stamp = self._handshake(sock)
            started = time.time()
            payload = json.dumps(
                {"id": self._msg_id, "method": method, "params": params or []},
                separators=(",", ":"),
            ).encode()
            packet = self._packet(did, stamp + int(time.time() - started), payload)
            sock.sendto(packet, (self._host, MIIO_PORT))

            # Keep reading until a packet with an actual body shows up; a late
            # duplicate of the handshake reply carries none.
            deadline = time.time() + TIMEOUT
            while time.time() < deadline:
                data, _ = sock.recvfrom(65536)
                if len(data) > 32:
                    return data
                _LOGGER.debug("%s: skipping bodyless %d-byte packet", method, len(data))
            raise MiioError(f"{method}: only bodyless packets")
        except socket.timeout as err:
            # Silence here usually means "this gateway does not implement that
            # method" rather than "the gateway is down" -- it behaves the same
            # either way, so callers must not read this as unreachable.
            raise MiioError(f"{method}: no response") from err
        except OSError as err:
            raise MiioError(f"{method}: {err}") from err
        finally:
            sock.close()

    # -- public ---------------------------------------------------------------

    def handshake(self) -> int:
        """Return the gateway's device id; raises if it is unreachable."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(TIMEOUT)
        try:
            did, _ = self._handshake(sock)
        except (socket.timeout, OSError) as err:
            raise MiioError(f"no miio handshake with {self._host}") from err
        finally:
            sock.close()
        return did

    def info(self) -> dict[str, Any]:
        """`miIO.info` -- firmware, wifi AP, IP, gateway MAC."""
        result = self._call("miIO.info")
        return result if isinstance(result, dict) else {}

    def camera_list(self) -> list[CameraInfo]:
        """Every camera this gateway serves.

        This is the single most useful call on the device: it yields the camera
        MAC needed to build a stream URL, plus battery and motion state, all
        locally and without waking the camera.
        """
        result = self._call("get_camera_list")
        if not isinstance(result, list):
            raise MiioError("get_camera_list returned no list")
        cameras = [CameraInfo.from_dict(item) for item in result if isinstance(item, dict)]
        if not cameras:
            raise MiioError("gateway reports no cameras")
        return cameras
