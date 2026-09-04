"""Constants for the IMILAB / Mijia EC2 integration."""

from __future__ import annotations

from typing import Final

DOMAIN: Final = "imilab_ec2"

# The gateway is the miot device; the cameras hang off it over the hidden
# `hodor-auth` WiFi. go2rtc needs this exact model string to pick the patched
# code path (it is a purely local switch -- it is never sent to the cloud).
GATEWAY_MODEL: Final = "chuangmi.gateway.ipc011"

# --- config entry keys -------------------------------------------------------

CONF_USER_ID: Final = "user_id"
CONF_PASS_TOKEN: Final = "pass_token"
# Stored so an expired token can be renewed without bothering anyone. Xiaomi
# rotates passTokens (an account migration will do it) and the only symptom is
# a silent 401 and cameras that stop -- not something a user should have to
# diagnose.
CONF_USERNAME: Final = "username"
CONF_PASSWORD: Final = "password"
CONF_GATEWAY_HOST: Final = "gateway_host"
CONF_GATEWAY_TOKEN: Final = "gateway_token"
CONF_GATEWAY_DID: Final = "gateway_did"
CONF_CAMERAS: Final = "cameras"

# --- options -----------------------------------------------------------------

CONF_RTSP_LISTEN: Final = "rtsp_listen"
CONF_API_LISTEN: Final = "api_listen"
CONF_WEBRTC_LISTEN: Final = "webrtc_listen"
CONF_WRITE_M3U: Final = "write_m3u"

# RTSP MUST stay reachable from the LAN: external players (Kodi via IPTV Simple)
# pull the streams straight off this port. Binding it to localhost silently
# breaks them, so ":8554" -- not "127.0.0.1:8554" -- is the default.
DEFAULT_RTSP_LISTEN: Final = ":8554"
DEFAULT_API_LISTEN: Final = ":1984"
DEFAULT_WEBRTC_LISTEN: Final = ":8555"

# Home Assistant bundles its own unpatched go2rtc on 127.0.0.1:18554, so these
# defaults do not collide with it.

# --- polling -----------------------------------------------------------------

# Two cadences on purpose: motion is useless if it lags, battery does not move.
# Polling costs the camera nothing -- it answers from the mains-powered gateway.
FAST_INTERVAL: Final = 15
SLOW_INTERVAL: Final = 900

# How often to confirm the account token still works. Cheap, and it catches a
# rotation before anyone notices the cameras are dark.
TOKEN_CHECK_INTERVAL: Final = 21600  # 6 hours
# Never retry a failed renewal faster than this, so a genuinely wrong password
# cannot turn into a login loop against Xiaomi.
TOKEN_RETRY_COOLDOWN: Final = 600

# --- streams -----------------------------------------------------------------

# Quality names come from the official app, not from the subtype number, which
# is NOT monotonic: 0 = HD (1080p, the cap), 1 = Speed (720p), 2 = Fluent
# (1080p but measurably the worst). Measured against the app's own traffic.
STREAM_QUALITIES: Final = {
    "": 0,
    "_fluent": 2,
    "_low": 1,
}

QUALITY_LABELS: Final = {
    "": "HD 1080p",
    "_fluent": "Fluent 1080p",
    "_low": "Speed 720p",
}

# Waking a battery camera and negotiating P2P takes a while; this is normal and
# must not be mistaken for a failure.
COLD_START_SECONDS: Final = 20
