"""Keeps the Xiaomi account token alive without bothering the user.

Modelled on what the Xiaomi Cloud Map Extractor does: hold the credentials and
simply log in again whenever the session is no longer good, rather than raising
a dialog. Xiaomi rotates passTokens -- an account migration will do it -- and
the only symptom is a silent `401` from the cloud and cameras that stop working.
That is a terrible thing to make somebody diagnose, and it is entirely
self-healing as long as we kept the credentials.

Two triggers, because either alone leaves a gap:

* **Periodic** -- confirm the token every few hours, so a rotation is caught
  before anyone notices the cameras are dark.
* **Reactive** -- go2rtc prints `401 Unauthorized` the moment the cloud refuses
  it, which is the earliest possible signal. We watch its output for that.

Escalating to a re-authentication prompt is the last resort, used only when we
genuinely cannot proceed alone: no stored password, or Xiaomi demanding
two-factor verification. Cloud Map Extractor only logs an error there; Home
Assistant gives us somewhere better to put it.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Awaitable, Callable

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.aiohttp_client import async_get_clientsession

from .const import (
    CONF_PASS_TOKEN,
    CONF_PASSWORD,
    CONF_USER_ID,
    CONF_USERNAME,
    TOKEN_RETRY_COOLDOWN,
)
from .xiaomi_cloud import VerificationRequired, XiaomiCloud, XiaomiCloudError

_LOGGER = logging.getLogger(__name__)


class TokenRenewer:
    """Renews the stored passToken and tells the caller when it changed."""

    def __init__(
        self,
        hass: HomeAssistant,
        entry: ConfigEntry,
        on_renewed: Callable[[], Awaitable[None]],
    ) -> None:
        self._hass = hass
        self._entry = entry
        self._on_renewed = on_renewed
        self._last_attempt = 0.0
        self._needs_user = False

    @property
    def needs_user(self) -> bool:
        """True once we have given up and asked a human."""
        return self._needs_user

    async def async_check(self, force: bool = False) -> bool:
        """Verify the token; renew it if it is dead. True if all is well."""
        if self._needs_user and not force:
            # Same guard Cloud Map Extractor uses: once verification is needed,
            # stop hammering the login endpoint.
            return False

        if await self._async_token_valid():
            return True

        _LOGGER.info("Xiaomi token no longer valid, renewing")
        return await self.async_renew()

    async def async_renew(self) -> bool:
        """Log in again with the stored credentials."""
        now = time.monotonic()
        if now - self._last_attempt < TOKEN_RETRY_COOLDOWN:
            return False
        self._last_attempt = now

        username = self._entry.data.get(CONF_USERNAME)
        password = self._entry.data.get(CONF_PASSWORD)
        if not username or not password:
            # Set up via the passToken route, so there is nothing to renew with.
            _LOGGER.warning(
                "Xiaomi token expired and no credentials are stored; "
                "re-authentication is required"
            )
            self._escalate()
            return False

        cloud = XiaomiCloud(async_get_clientsession(self._hass))
        try:
            await cloud.async_login(username, password)
        except VerificationRequired as err:
            _LOGGER.warning(
                "Xiaomi wants a verification code before it will renew the "
                "session; it has been sent to %s. Re-authentication is needed",
                err.destination,
            )
            self._escalate()
            return False
        except XiaomiCloudError as err:
            _LOGGER.error("Could not renew the Xiaomi session: %s", err)
            return False

        if not cloud.pass_token:
            _LOGGER.error("Renewal returned no passToken")
            return False

        self._hass.config_entries.async_update_entry(
            self._entry,
            data={
                **self._entry.data,
                CONF_USER_ID: cloud.user_id or self._entry.data.get(CONF_USER_ID),
                CONF_PASS_TOKEN: cloud.pass_token,
            },
        )
        self._needs_user = False
        _LOGGER.info("Xiaomi session renewed")
        await self._on_renewed()
        return True

    async def _async_token_valid(self) -> bool:
        """Cheap round trip that proves the stored token still authenticates."""
        user_id = self._entry.data.get(CONF_USER_ID)
        pass_token = self._entry.data.get(CONF_PASS_TOKEN)
        if not user_id or not pass_token:
            return False

        cloud = XiaomiCloud(async_get_clientsession(self._hass))
        try:
            await cloud.async_login_with_token(user_id, pass_token)
        except XiaomiCloudError as err:
            _LOGGER.debug("Token check failed: %s", err)
            return False
        return True

    def _escalate(self) -> None:
        """Hand it to the user -- only when we truly cannot do it ourselves."""
        if self._needs_user:
            return
        self._needs_user = True
        self._entry.async_start_reauth(self._hass)
