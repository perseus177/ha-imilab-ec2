"""Diagnostics download for an EC2 gateway entry.

Everything needed to tell a broken account, a silent gateway and a broken
stream apart, in one file a user can attach to an issue -- without any
credential in it.
"""

from __future__ import annotations

from dataclasses import asdict
from typing import Any

from homeassistant.components.diagnostics import async_redact_data
from homeassistant.core import HomeAssistant

from . import Ec2ConfigEntry
from .const import (
    CONF_GATEWAY_TOKEN,
    CONF_PASS_TOKEN,
    CONF_PASSWORD,
    CONF_USER_ID,
    CONF_USERNAME,
)

TO_REDACT = {CONF_PASS_TOKEN, CONF_PASSWORD, CONF_USERNAME, CONF_GATEWAY_TOKEN}


async def async_get_config_entry_diagnostics(
    hass: HomeAssistant, entry: Ec2ConfigEntry
) -> dict[str, Any]:
    """Return diagnostics for one gateway entry."""
    data: dict[str, Any] = {
        "entry": async_redact_data(dict(entry.data), TO_REDACT),
        "options": dict(entry.options),
        # Present or not matters more than the value, which stays private.
        "has_pass_token": bool(entry.data.get(CONF_PASS_TOKEN)),
        "has_gateway_token": bool(entry.data.get(CONF_GATEWAY_TOKEN)),
        "has_credentials": bool(entry.data.get(CONF_PASSWORD)),
        "user_id_set": bool(entry.data.get(CONF_USER_ID)),
    }

    runtime = getattr(entry, "runtime_data", None)
    if runtime is None:
        # Setup failed; the entry's own state and reason say why.
        data["state"] = str(entry.state)
        data["reason"] = entry.reason
        return data

    coordinator = runtime.coordinator
    manager = runtime.go2rtc
    data["gateway"] = {
        "live": coordinator.live,
        "last_update_success": coordinator.last_update_success,
        "last_error": coordinator.last_error,
        "diagnosis": coordinator.diagnosis,
        "source": coordinator.source,
        "cloud_error": coordinator.cloud_error,
        "last_motion": coordinator.last_motion.isoformat()
        if coordinator.last_motion
        else None,
        "last_event": coordinator.last_event,
        "event_reply": str(coordinator.event_reply)[:2000],
        "cameras": [asdict(camera) for camera in (coordinator.data or {}).values()],
    }
    data["go2rtc"] = {
        "pid": manager.pid,
        "restarts": manager.restarts,
        "last_exit_code": manager.last_exit_code,
        "api_listen": manager.api_listen,
        "rtsp_listen": manager.rtsp_listen,
        "webrtc_listen": manager.webrtc_listen,
        # Already redacted as it was read.
        "output": list(manager.output),
    }
    data["p2p_keys"] = {
        did: {
            key: value.isoformat() if hasattr(value, "isoformat") else value
            for key, value in state.items()
        }
        for did, state in manager.p2p.items()
    }
    renewer = runtime.renewer
    data["account"] = {
        "needs_user": getattr(renewer, "needs_user", None),
    }
    return data
