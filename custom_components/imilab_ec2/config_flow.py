"""Config flow for IMILAB / Mijia EC2 cameras.

Sign in, and the gateways -- with their addresses, device ids and local miio
tokens -- are found for you. Nothing has to be typed in by hand.

Why signing in comes first, rather than scanning the network first: a miio
broadcast finds every miio device on the LAN, but the reply carries only a
device id. The *model* lives behind the encrypted `miIO.info`, which needs a
token, so a scan alone can never say "this one is an EC2 gateway". The cloud
knows the model; the scan knows the current address. Using both, and matching
them on device id, beats either alone -- and streaming needs the account
regardless, because every connection fetches fresh P2P keys from the cloud.

Two-factor accounts follow the approach the Xiaomi Cloud Map Extractor uses:
Xiaomi hands back a verification URL, the user opens it in their own browser,
and the login is then retried. Note that Xiaomi ties that trust to the **public
IP address**, so the verification has to happen from the same network as Home
Assistant.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping
from typing import Any

import voluptuous as vol
from homeassistant.config_entries import ConfigFlow, ConfigFlowResult
from homeassistant.helpers import config_validation as cv
from homeassistant.helpers.aiohttp_client import async_create_clientsession
from homeassistant.helpers.selector import (
    SelectSelector,
    SelectSelectorConfig,
    SelectSelectorMode,
)

from .const import (
    CONF_CAMERAS,
    CONF_GATEWAY_DID,
    CONF_GATEWAY_HOST,
    CONF_GATEWAY_TOKEN,
    CONF_PASS_TOKEN,
    CONF_PASSWORD,
    CONF_USER_ID,
    CONF_USERNAME,
    DOMAIN,
)
from .discovery import discover
from .miio import MiioError, MiioGateway
from .xiaomi_cloud import (
    CloudDevice,
    TwoFactorRequired,
    XiaomiCloud,
    XiaomiCloudError,
)

_LOGGER = logging.getLogger(__name__)


CONF_GATEWAY = "gateway"

CREDENTIALS_SCHEMA = vol.Schema(
    {vol.Required(CONF_USERNAME): cv.string, vol.Required(CONF_PASSWORD): cv.string}
)

TOKEN_SCHEMA = vol.Schema(
    {vol.Required(CONF_USER_ID): cv.string, vol.Required(CONF_PASS_TOKEN): cv.string}
)


class Ec2ConfigFlow(ConfigFlow, domain=DOMAIN):
    """Sign in, discover gateways, add one."""

    VERSION = 1

    def __init__(self) -> None:
        self._cloud: XiaomiCloud | None = None
        self._username: str | None = None
        self._password: str | None = None
        self._two_factor_url: str | None = None
        self._gateways: list[CloudDevice] = []
        self._lan: dict[int, str] = {}

    # -- entry points ---------------------------------------------------------

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Choose how to sign in."""
        return self.async_show_menu(
            step_id="user", menu_options=["credentials", "token"]
        )

    async def async_step_credentials(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Sign in with a Xiaomi username and password."""
        errors: dict[str, str] = {}

        if user_input is not None:
            self._username = user_input[CONF_USERNAME].strip()
            self._password = user_input[CONF_PASSWORD]
            result = await self._async_login()
            if result is not None:
                return result
            errors["base"] = self._last_error

        return self.async_show_form(
            step_id="credentials", data_schema=CREDENTIALS_SCHEMA, errors=errors
        )

    async def async_step_token(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Sign in with a user ID and passToken -- no password, no 2FA."""
        errors: dict[str, str] = {}

        if user_input is not None:
            cloud = self._async_cloud()
            try:
                await cloud.async_login_with_token(
                    user_input[CONF_USER_ID].strip(),
                    user_input[CONF_PASS_TOKEN].strip(),
                )
            except XiaomiCloudError as err:
                _LOGGER.debug("passToken login failed: %s", err)
                errors["base"] = "invalid_auth"
            else:
                self._cloud = cloud
                return await self._async_after_login()

        return self.async_show_form(
            step_id="token", data_schema=TOKEN_SCHEMA, errors=errors
        )

    async def async_step_two_factor(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Wait for the user to verify in their browser, then retry.

        We deliberately do not try to submit the code ourselves: Xiaomi's
        verification endpoints differ between phone and email accounts and are
        brittle to drive. Letting the user complete it in a browser works for
        both, and Xiaomi then trusts the public IP.
        """
        errors: dict[str, str] = {}

        if user_input is not None:
            result = await self._async_login()
            if result is not None:
                return result
            # Still refused. Say which of the two reasons it was, rather than
            # silently redrawing the same dialog.
            errors["base"] = self._last_error

        return self.async_show_form(
            step_id="two_factor",
            data_schema=vol.Schema({}),
            errors=errors,
            description_placeholders={"url": self._two_factor_url or ""},
        )

    async def async_step_reauth(
        self, entry_data: Mapping[str, Any]
    ) -> ConfigFlowResult:
        """Last resort when the token cannot be renewed on its own.

        Normally an expired token never reaches the user at all -- `TokenRenewer`
        signs in again with the stored credentials. This step only appears when
        that is impossible: the entry was set up with a passToken and has no
        credentials to renew with, or Xiaomi is demanding verification.
        """
        return await self.async_step_reauth_confirm()

    async def async_step_reauth_confirm(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Re-run the login and update the stored token in place."""
        errors: dict[str, str] = {}

        if user_input is not None:
            self._username = user_input[CONF_USERNAME].strip()
            self._password = user_input[CONF_PASSWORD]
            cloud = self._async_cloud()
            try:
                await cloud.async_login(self._username, self._password)
            except TwoFactorRequired as err:
                self._two_factor_url = err.notification_url
                return await self.async_step_two_factor()
            except XiaomiCloudError as err:
                _LOGGER.debug("Re-authentication failed: %s", err)
                errors["base"] = "invalid_auth"
            else:
                entry = self._get_reauth_entry()
                return self.async_update_reload_and_abort(
                    entry,
                    data={
                        **entry.data,
                        CONF_USER_ID: cloud.user_id,
                        CONF_PASS_TOKEN: cloud.pass_token,
                        # Store them this time, so the next rotation renews
                        # itself instead of coming back here.
                        CONF_USERNAME: self._username,
                        CONF_PASSWORD: self._password,
                    },
                )

        return self.async_show_form(
            step_id="reauth_confirm", data_schema=CREDENTIALS_SCHEMA, errors=errors
        )

    # -- discovery ------------------------------------------------------------

    async def async_step_select(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Pick which discovered gateway to add."""
        if user_input is not None:
            chosen = next(
                (gw for gw in self._gateways if gw.did == user_input[CONF_GATEWAY]),
                None,
            )
            if chosen is None:
                return self.async_abort(reason="gateway_gone")
            return await self._async_create(chosen)

        options = [
            {
                "value": gateway.did,
                "label": f"{gateway.name} ({self._address_for(gateway)})",
            }
            for gateway in self._gateways
        ]
        return self.async_show_form(
            step_id="select",
            data_schema=vol.Schema(
                {
                    vol.Required(CONF_GATEWAY): SelectSelector(
                        SelectSelectorConfig(
                            options=options, mode=SelectSelectorMode.LIST
                        )
                    )
                }
            ),
        )

    def _async_cloud(self) -> XiaomiCloud:
        """The one cloud client for this flow.

        Reused across retries on purpose. Xiaomi ties a completed verification
        to the `deviceId` cookie, so building a fresh client for each attempt
        makes every retry look like a brand new device and the verification the
        user just did never applies. It also keeps the cookie jar coherent
        across the three-request login sequence, which is why this gets its own
        session rather than the one shared with every other integration.
        """
        if self._cloud is None:
            self._cloud = XiaomiCloud(async_create_clientsession(self.hass))
        return self._cloud

    async def _async_login(self) -> ConfigFlowResult | None:
        """Try the username/password login.

        Returns the next step, or None when the login did not complete -- the
        caller then re-renders its own form with `self._last_error`. It must not
        call a step itself: doing so returns a form the caller mistakes for
        success, and the user sees the dialog redraw with no explanation.
        """
        assert self._username is not None and self._password is not None
        cloud = self._async_cloud()
        try:
            await cloud.async_login(self._username, self._password)
        except TwoFactorRequired as err:
            self._two_factor_url = err.notification_url
            self._last_error = "two_factor_pending"
            return None
        except XiaomiCloudError as err:
            _LOGGER.debug("Login failed: %s", err)
            self._last_error = "invalid_auth"
            return None
        return await self._async_after_login()

    async def _async_after_login(self) -> ConfigFlowResult:
        """Ask the cloud for gateways, then confirm their addresses on the LAN."""
        assert self._cloud is not None
        try:
            self._gateways = await self._cloud.async_find_gateways()
        except XiaomiCloudError as err:
            _LOGGER.debug("Could not list devices: %s", err)
            return self.async_abort(reason="cannot_connect")

        if not self._gateways:
            return self.async_abort(reason="no_gateways")

        # The cloud's `localip` goes stale whenever DHCP moves a device, so
        # prefer an address we can actually see answering right now.
        self._lan = await self.hass.async_add_executor_job(discover)

        configured = {entry.unique_id for entry in self._async_current_entries()}
        self._gateways = [
            gateway for gateway in self._gateways if gateway.did not in configured
        ]
        if not self._gateways:
            return self.async_abort(reason="already_configured")
        if len(self._gateways) == 1:
            return await self._async_create(self._gateways[0])
        return await self.async_step_select()

    def _address_for(self, gateway: CloudDevice) -> str:
        """The LAN address if we saw it answer, else whatever the cloud said."""
        try:
            did = int(gateway.did)
        except (TypeError, ValueError):
            did = -1
        return self._lan.get(did) or gateway.local_ip or ""

    async def _async_create(self, gateway: CloudDevice) -> ConfigFlowResult:
        """Build the entry, discovering the cameras behind this gateway."""
        assert self._cloud is not None
        host = self._address_for(gateway)
        if not host:
            return self.async_abort(reason="no_address")

        await self.async_set_unique_id(gateway.did)
        self._abort_if_unique_id_configured()

        cameras: list[dict[str, str]] = []
        if gateway.token:
            client = MiioGateway(host, gateway.token)
            try:
                found = await self.hass.async_add_executor_job(client.camera_list)
            except MiioError as err:
                # Not fatal: streaming needs the account, not this token. A
                # rotated token costs us the sensors, not the video.
                _LOGGER.info(
                    "Gateway %s did not answer get_camera_list (%s); "
                    "continuing without local camera state",
                    host,
                    err,
                )
            else:
                cameras = [{"mac": cam.mac, "name": cam.name} for cam in found]

        data = {
            CONF_GATEWAY_HOST: host,
            CONF_GATEWAY_DID: gateway.did,
            CONF_GATEWAY_TOKEN: gateway.token or "",
            CONF_USER_ID: self._cloud.user_id,
            CONF_PASS_TOKEN: self._cloud.pass_token,
            CONF_CAMERAS: cameras,
        }
        if self._username and self._password:
            # Kept so an expired token renews itself. Without these, a rotation
            # means the cameras go dark until somebody signs in again by hand --
            # which is exactly the failure this integration exists to avoid.
            data[CONF_USERNAME] = self._username
            data[CONF_PASSWORD] = self._password

        return self.async_create_entry(
            title=gateway.name or f"EC2 gateway {host}", data=data
        )

    _last_error: str = "invalid_auth"
