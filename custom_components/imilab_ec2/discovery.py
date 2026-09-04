"""Find miio devices on the local network.

The miio handshake is unencrypted, so every miio device on the LAN answers a
broadcast whether or not we hold its token, and the reply carries its device id.

That is both the strength and the limit of this: it tells us *where* the miio
devices are, but not *what* they are -- the model only comes from the encrypted
`miIO.info`, which needs a valid token. So discovery on its own cannot say "this
one is an EC2 gateway".

It is still worth doing, because the cloud knows the model and the device id but
often reports a stale `localip`. Matching the two by device id gives us the
model from the cloud and the *current* address from the LAN.
"""

from __future__ import annotations

import logging
import socket
import struct
import time

_LOGGER = logging.getLogger(__name__)

MIIO_PORT = 54321
HELLO = b"\x21\x31\x00\x20" + b"\xff" * 28
LISTEN_SECONDS = 4.0


def discover(timeout: float = LISTEN_SECONDS) -> dict[int, str]:
    """Broadcast a miio hello and collect {device_id: ip}.

    Blocking; call from an executor.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.settimeout(0.5)

    found: dict[int, str] = {}
    try:
        for address in _broadcast_addresses():
            try:
                sock.sendto(HELLO, (address, MIIO_PORT))
            except OSError as err:
                _LOGGER.debug("Broadcast to %s failed: %s", address, err)

        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                data, addr = sock.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                break
            if len(data) < 16 or data[:2] != b"\x21\x31":
                continue
            did, _stamp = struct.unpack(">II", data[8:16])
            if did and did != 0xFFFFFFFF:
                found.setdefault(did, addr[0])
    finally:
        sock.close()

    _LOGGER.debug("miio discovery found %d device(s)", len(found))
    return found


def _broadcast_addresses() -> list[str]:
    """Global broadcast plus this host's own subnet broadcast.

    Home Assistant runs host-networked here, so the local interface address is
    the LAN address the cameras live on. Some networks drop 255.255.255.255 but
    pass a directed subnet broadcast, so send both.
    """
    addresses = ["255.255.255.255"]
    try:
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            # No traffic is actually sent; this just picks the default route.
            probe.connect(("8.8.8.8", 80))
            local_ip = probe.getsockname()[0]
        finally:
            probe.close()
    except OSError:
        return addresses

    parts = local_ip.split(".")
    if len(parts) == 4:
        # Assume a /24, which is what home networks overwhelmingly are.
        addresses.append(f"{parts[0]}.{parts[1]}.{parts[2]}.255")
    return addresses
