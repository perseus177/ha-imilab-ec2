"""IMILAB / Mijia EC2 cameras."""

from __future__ import annotations

import logging
from datetime import timedelta
from pathlib import Path

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import Platform
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryNotReady
from homeassistant.helpers.event import async_track_time_interval

from .const import (
    CONF_API_LISTEN,
    CONF_CAMERAS,
    CONF_GATEWAY_DID,
    CONF_GATEWAY_HOST,
    CONF_GATEWAY_TOKEN,
    CONF_PASS_TOKEN,
    CONF_RTSP_LISTEN,
    CONF_USER_ID,
    CONF_WEBRTC_LISTEN,
    DEFAULT_API_LISTEN,
    DEFAULT_RTSP_LISTEN,
    DEFAULT_WEBRTC_LISTEN,
    DOMAIN,
    TOKEN_CHECK_INTERVAL,
)
from .auth import TokenRenewer
from .coordinator import Ec2Coordinator, Ec2RuntimeData, static_camera
from .go2rtc_manager import Go2rtcError, Go2rtcManager, build_streams
from .miio import MiioError, MiioGateway

_LOGGER = logging.getLogger(__name__)

PLATFORMS = [Platform.CAMERA]

type Ec2ConfigEntry = ConfigEntry[Ec2RuntimeData]


async def async_setup_entry(hass: HomeAssistant, entry: Ec2ConfigEntry) -> bool:
    """Set up one gateway."""
    host = entry.data[CONF_GATEWAY_HOST]

    # The miio token is optional: without it we cannot read sensor state, but
    # streaming works regardless, and that is the point of the integration.
    token = entry.data.get(CONF_GATEWAY_TOKEN) or ""
    gateway = MiioGateway(host, token) if token else None

    fallback = [
        static_camera(camera["mac"], camera.get("name", camera["mac"]))
        for camera in entry.data.get(CONF_CAMERAS, [])
    ]
    coordinator = Ec2Coordinator(hass, host, gateway, fallback)
    await coordinator.async_config_entry_first_refresh()

    # go2rtc is a singleton shared by every gateway entry: one process, one
    # config file, one set of ports.
    manager = _async_get_manager(hass)
    manager.api_listen = entry.options.get(CONF_API_LISTEN, DEFAULT_API_LISTEN)
    manager.rtsp_listen = entry.options.get(CONF_RTSP_LISTEN, DEFAULT_RTSP_LISTEN)
    manager.webrtc_listen = entry.options.get(CONF_WEBRTC_LISTEN, DEFAULT_WEBRTC_LISTEN)

    entry.runtime_data = Ec2RuntimeData(
        coordinator=coordinator,
        go2rtc=manager,
        gateway_id=f"gateway_{entry.data[CONF_GATEWAY_DID]}",
        lan_host=host_ip_for_players(hass, host),
    )

    # Renew the account token by ourselves whenever it goes stale, the way the
    # Xiaomi Cloud Map Extractor does: log in again rather than raise a dialog.
    async def _async_after_renewal() -> None:
        """A fresh token is stored -- push it into go2rtc and reconnect."""
        await _async_rebuild_go2rtc(hass)
        await manager.async_stop()
        await manager.async_start()

    renewer = TokenRenewer(hass, entry, _async_after_renewal)
    entry.runtime_data.renewer = renewer
    # go2rtc sees the refusal first; let it pull the trigger.
    manager.on_auth_failure = renewer.async_check

    try:
        await manager.async_ensure_binary()
        await _async_rebuild_go2rtc(hass)
        await manager.async_start()
    except Go2rtcError as err:
        raise ConfigEntryNotReady(f"streaming backend unavailable: {err}") from err

    # Catch a rotation before anybody notices the cameras are dark.
    entry.async_on_unload(
        async_track_time_interval(
            hass,
            lambda _now: hass.async_create_task(renewer.async_check()),
            timedelta(seconds=TOKEN_CHECK_INTERVAL),
        )
    )

    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    entry.async_on_unload(entry.add_update_listener(_async_update_listener))
    return True


async def async_unload_entry(hass: HomeAssistant, entry: Ec2ConfigEntry) -> bool:
    """Unload a gateway, stopping go2rtc once the last one goes."""
    unloaded = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if not unloaded:
        return False

    remaining = [
        other
        for other in hass.config_entries.async_entries(DOMAIN)
        if other.entry_id != entry.entry_id and other.state.recoverable
    ]
    if remaining:
        await _async_rebuild_go2rtc(hass, skip_entry_id=entry.entry_id)
    else:
        manager = _async_get_manager(hass)
        await manager.async_stop()
        hass.data.pop(DOMAIN, None)
    return True


async def _async_update_listener(hass: HomeAssistant, entry: Ec2ConfigEntry) -> None:
    """Re-render the go2rtc config when options change."""
    await hass.config_entries.async_reload(entry.entry_id)


def _async_get_manager(hass: HomeAssistant) -> Go2rtcManager:
    """The one go2rtc process, created on first use."""
    store = hass.data.setdefault(DOMAIN, {})
    if "go2rtc" not in store:
        store["go2rtc"] = Go2rtcManager(hass, Path(hass.config.path(DOMAIN)))
    return store["go2rtc"]


async def _async_rebuild_go2rtc(
    hass: HomeAssistant, skip_entry_id: str | None = None
) -> None:
    """Render go2rtc.yaml from every loaded gateway entry.

    Every camera gets all three qualities. The HD stream backs the Home
    Assistant camera entity; the others exist for external players -- the Kodi
    IPTV playlist points at them by name, so the naming is a contract.
    """
    manager = _async_get_manager(hass)
    accounts: dict[str, str] = {}
    streams = []

    for entry in hass.config_entries.async_entries(DOMAIN):
        if entry.entry_id == skip_entry_id:
            continue
        data = getattr(entry, "runtime_data", None)
        if data is None:
            continue
        accounts[entry.data[CONF_USER_ID]] = entry.data[CONF_PASS_TOKEN]
        streams.extend(
            build_streams(
                user_id=entry.data[CONF_USER_ID],
                gateway_host=entry.data[CONF_GATEWAY_HOST],
                gateway_did=entry.data[CONF_GATEWAY_DID],
                cameras=list(data.coordinator.data.values()),
            )
        )

    await manager.async_write_config(accounts, streams)


def host_ip_for_players(hass: HomeAssistant, gateway_host: str) -> str:
    """The address external players should use to reach our RTSP port.

    Home Assistant runs host-networked here, so go2rtc listens on the same LAN
    address as Home Assistant itself. Fall back to the configured internal URL
    when we cannot work it out.
    """
    try:
        from homeassistant.helpers.network import get_url

        url = get_url(hass, allow_external=False, allow_ip=True)
        return url.split("://", 1)[-1].rsplit(":", 1)[0]
    except Exception:  # noqa: BLE001 - best effort only
        return gateway_host


__all__ = ["MiioError", "async_setup_entry", "async_unload_entry"]
