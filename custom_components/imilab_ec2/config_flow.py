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

The first choice is a QR code, as in the Xiaomi Cloud Map Extractor: the owner
scans it in the Mi Home app (or opens the link and signs in on Xiaomi's page),
and Xiaomi completes the login for this flow by answering a long poll. No
password, captcha or verification code passes through here, so Xiaomi's daily
code quota cannot block it.

For the password route, challenges -- a captcha, a verification code, or both,
in any order and more than once -- are handled here rather than by sending the
user to a web page.
Verification is started from this client, Xiaomi sends the code, and the code
is submitted from this client too, which is the approach go2rtc takes and the
reason the same account signs in there on the first attempt. Sending the user
to a browser instead completes a sign-in for the *browser* and leaves this one
exactly where it was, which loops forever.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Mapping
from typing import Any

import voluptuous as vol
from homeassistant.config_entries import (
    SOURCE_REAUTH,
    ConfigEntry,
    ConfigFlow,
    ConfigFlowResult,
    OptionsFlow,
)
from homeassistant.core import callback
from homeassistant.helpers import config_validation as cv
from homeassistant.helpers.aiohttp_client import async_create_clientsession
from homeassistant.helpers.selector import (
    SelectSelector,
    SelectSelectorConfig,
    SelectSelectorMode,
    TextSelector,
    TextSelectorConfig,
)

from .const import (
    CONF_API_LISTEN,
    CONF_CAMERAS,
    CONF_GATEWAY_DID,
    CONF_GATEWAY_HOST,
    CONF_GATEWAY_TOKEN,
    CONF_PASS_TOKEN,
    CONF_PASSWORD,
    CONF_RTSP_LISTEN,
    CONF_USER_ID,
    CONF_USERNAME,
    CONF_WEBRTC_LISTEN,
    DEFAULT_API_LISTEN,
    DEFAULT_RTSP_LISTEN,
    DEFAULT_WEBRTC_LISTEN,
    DOMAIN,
)
from .discovery import discover
from .miio import CameraInfo, MiioError, MiioGateway
from .xiaomi_cloud import (
    CaptchaRequired,
    CloudDevice,
    CodeQuotaExhausted,
    QrExpired,
    QrLogin,
    VerificationRequired,
    XiaomiCloud,
    XiaomiCloudError,
)

_LOGGER = logging.getLogger(__name__)


CONF_GATEWAY = "gateway"
CONF_COUNTRY = "country"
CONF_CAPTCHA = "captcha"
CONF_CODE = "code"
CONF_MACS = "macs"

# Where the account lives. The Xiaomi app calls mainland China the default, and
# it is served from the bare host; every other region is a subdomain.
COUNTRY_OPTIONS = [
    {"value": "cn", "label": "Chinese mainland"},
    {"value": "de", "label": "Europe"},
    {"value": "us", "label": "United States"},
    {"value": "ru", "label": "Russia"},
    {"value": "sg", "label": "Singapore"},
    {"value": "i2", "label": "India"},
    {"value": "tw", "label": "Taiwan"},
    {"value": "in", "label": "India (legacy)"},
]


def _country_selector() -> SelectSelector:
    return SelectSelector(
        SelectSelectorConfig(options=COUNTRY_OPTIONS, mode=SelectSelectorMode.DROPDOWN)
    )


CREDENTIALS_SCHEMA = vol.Schema(
    {
        vol.Required(CONF_USERNAME): cv.string,
        vol.Required(CONF_PASSWORD): cv.string,
        vol.Required(CONF_COUNTRY, default="cn"): _country_selector(),
    }
)

REGION_SCHEMA = vol.Schema(
    {vol.Required(CONF_COUNTRY, default="cn"): _country_selector()}
)

CAPTCHA_SCHEMA = vol.Schema({vol.Required(CONF_CAPTCHA): cv.string})

CODE_SCHEMA = vol.Schema({vol.Required(CONF_CODE): cv.string})


def _macs_schema(default: str = "") -> vol.Schema:
    return vol.Schema(
        {
            vol.Required(CONF_MACS, default=default): TextSelector(
                TextSelectorConfig(multiline=True)
            )
        }
    )


def parse_cameras(text: str) -> list[dict[str, str]] | None:
    """Read camera MACs typed by hand; None if any of them is not a MAC.

    Accepts `B8DE5E4D1C25` or `B8DE5E4D1C25=Balcony`, separated by commas or
    newlines. Colons and dashes inside a MAC are ignored, so a MAC copied in
    the usual `B8:DE:5E:4D:1C:25` form works too.
    """
    cameras: list[dict[str, str]] = []
    seen: set[str] = set()
    for item in text.replace(",", "\n").splitlines():
        item = item.strip()
        if not item:
            continue
        mac, _, name = item.partition("=")
        mac = mac.strip().replace(":", "").replace("-", "").upper()
        if len(mac) != 12 or any(c not in "0123456789ABCDEF" for c in mac):
            return None
        if mac in seen:
            continue
        seen.add(mac)
        # No name: the camera is then named after its gateway.
        cameras.append({"mac": mac, "name": name.strip()})
    return cameras or None


def format_cameras(cameras: list[dict[str, str]]) -> str:
    """The inverse of `parse_cameras`, to prefill the form."""
    return "\n".join(f"{c['mac']}={c.get('name', '')}" for c in cameras)


TOKEN_SCHEMA = vol.Schema(
    {
        vol.Required(CONF_USER_ID): cv.string,
        vol.Required(CONF_PASS_TOKEN): cv.string,
        vol.Required(CONF_COUNTRY, default="cn"): _country_selector(),
    }
)


class Ec2ConfigFlow(ConfigFlow, domain=DOMAIN):
    """Sign in, discover gateways, add one."""

    VERSION = 1

    @staticmethod
    @callback
    def async_get_options_flow(config_entry: ConfigEntry) -> Ec2OptionsFlow:
        return Ec2OptionsFlow()

    def __init__(self) -> None:
        self._cloud: XiaomiCloud | None = None
        self._username: str | None = None
        self._password: str | None = None
        self._code_destination: str = ""
        self._captcha_image: str | None = None
        self._country: str = "cn"
        self._gateways: list[CloudDevice] = []
        self._lan: dict[int, str] = {}
        self._qr: QrLogin | None = None
        self._qr_task: asyncio.Task[None] | None = None
        self._qr_error: str | None = None
        # An entry waiting only for its camera list, when the gateway would
        # not tell us which cameras it serves.
        self._pending_title: str = ""
        self._pending_data: dict[str, Any] = {}

    # -- entry points ---------------------------------------------------------

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Choose how to sign in."""
        return self.async_show_menu(
            step_id="user", menu_options=["qr", "credentials", "token"]
        )

    async def async_step_qr(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Pick the region, then show the QR code.

        The region is asked for first because the QR login itself does not
        reveal it, and asking the wrong one finds no devices.
        """
        errors: dict[str, str] = {}
        if self._qr_error:
            errors["base"], self._qr_error = self._qr_error, None
        elif user_input is None and self.source == SOURCE_REAUTH:
            # Signing in again lists no devices, so the region does not matter.
            user_input = {}

        if user_input is not None:
            self._country = user_input.get(CONF_COUNTRY, "cn")
            cloud = self._async_cloud()
            try:
                self._qr = await cloud.async_qr_start()
            except XiaomiCloudError as err:
                _LOGGER.warning("Could not get a login QR code from Xiaomi: %s", err)
                errors["base"] = "cannot_connect"
            else:
                self._qr_task = None
                return await self.async_step_qr_scan()

        return self.async_show_form(
            step_id="qr", data_schema=REGION_SCHEMA, errors=errors
        )

    async def async_step_qr_scan(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Show the code and wait for Xiaomi to confirm it was scanned."""
        assert self._qr is not None
        if self._qr_task is None:
            self._qr_task = self.hass.async_create_task(
                self._async_cloud().async_qr_wait()
            )

        if not self._qr_task.done():
            return self.async_show_progress(
                step_id="qr_scan",
                progress_action="qr_scan",
                description_placeholders={
                    "qr_image": self._qr.image_data_uri,
                    "login_url": self._qr.login_url,
                },
                progress_task=self._qr_task,
            )

        err = self._qr_task.exception()
        self._qr_task = None
        if err is None:
            return self.async_show_progress_done(next_step_id="qr_done")
        if isinstance(err, QrExpired):
            self._qr_error = "qr_expired"
        else:
            _LOGGER.warning("QR sign-in did not complete: %s", err)
            self._qr_error = "qr_failed"
        return self.async_show_progress_done(next_step_id="qr")

    @callback
    def async_remove(self) -> None:
        """Stop waiting for a scan when the dialog is closed."""
        if self._qr_task is not None and not self._qr_task.done():
            self._qr_task.cancel()

    async def async_step_qr_done(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Signed in by QR code."""
        return await self._async_after_login()

    async def async_step_credentials(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Sign in with a Xiaomi username and password."""
        errors: dict[str, str] = {}

        if user_input is not None:
            self._username = user_input[CONF_USERNAME].strip()
            self._password = user_input[CONF_PASSWORD]
            self._country = user_input.get(CONF_COUNTRY, "cn")
            result = await self._async_login()
            if result is not None:
                return result
            nxt = await self._async_next("credentials")
            if nxt is not None:
                return nxt
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
            self._country = user_input.get(CONF_COUNTRY, "cn")
            cloud = self._async_cloud()
            try:
                await cloud.async_login_with_token(
                    user_input[CONF_USER_ID].strip(),
                    user_input[CONF_PASS_TOKEN].strip(),
                )
            except XiaomiCloudError as err:
                _LOGGER.warning("Xiaomi refused the passToken: %s", err)
                errors["base"] = "invalid_auth"
            else:
                self._cloud = cloud
                return await self._async_after_login()

        return self.async_show_form(
            step_id="token", data_schema=TOKEN_SCHEMA, errors=errors
        )

    async def async_step_captcha(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Show the captcha image and take the answer.

        The image cannot simply be linked: Xiaomi ties it to an `ick` cookie
        held by the client that will submit the answer, so a browser opening
        the same URL would be shown a different one. It is therefore fetched
        here and rendered inline.
        """
        errors: dict[str, str] = {}

        if user_input is not None:
            result = await self._async_login(user_input[CONF_CAPTCHA].strip())
            if result is not None:
                return result
            nxt = await self._async_next("captcha")
            if nxt is not None:
                return nxt
            # A fresh captcha comes with every refusal; the old one is spent.
            errors["base"] = (
                "captcha_wrong"
                if self._last_error == "captcha_required"
                else self._last_error
            )

        return self.async_show_form(
            step_id="captcha",
            data_schema=CAPTCHA_SCHEMA,
            errors=errors,
            description_placeholders={"image": self._captcha_image or ""},
        )

    async def async_step_code(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Take the code Xiaomi has already sent.

        No browser trip: the verification is started and the code requested
        from here, so all that is left is to type in what arrived. Sending the
        user to a web page instead completes a sign-in for the browser and
        leaves this one exactly where it was, which is why that approach
        looped.
        """
        errors: dict[str, str] = {}

        if user_input is not None:
            result = await self._async_login(verify_code=user_input[CONF_CODE].strip())
            if result is not None:
                return result
            nxt = await self._async_next("code")
            if nxt is not None:
                return nxt
            errors["base"] = self._last_error

        return self.async_show_form(
            step_id="code",
            data_schema=CODE_SCHEMA,
            errors=errors,
            description_placeholders={"destination": self._code_destination},
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
        """Offer the same ways in as the first setup.

        Every route ends in `_async_after_login`, which updates this entry in
        place instead of creating a new one. Before, only the password route
        existed here, and a captcha or code on the way sent it into the setup
        path, which could never finish a re-authentication.
        """
        return self.async_show_menu(
            step_id="reauth_confirm", menu_options=["qr", "credentials", "token"]
        )

    async def _async_finish_reauth(self) -> ConfigFlowResult:
        """Store the new token on the entry being re-authenticated."""
        assert self._cloud is not None
        entry = self._get_reauth_entry()
        stored_user = entry.data.get(CONF_USER_ID)
        if stored_user and self._cloud.user_id and stored_user != self._cloud.user_id:
            # A different account cannot stream these cameras; refuse rather
            # than overwrite a working owner with a shared user.
            return self.async_abort(reason="wrong_account")
        data = {
            **entry.data,
            CONF_USER_ID: self._cloud.user_id or stored_user,
            CONF_PASS_TOKEN: self._cloud.pass_token,
        }
        if self._username and self._password:
            # Stored this time, so the next expiry renews itself instead of
            # coming back here.
            data[CONF_USERNAME] = self._username
            data[CONF_PASSWORD] = self._password
        return self.async_update_reload_and_abort(entry, data=data)

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

    async def _async_next(self, current: str) -> ConfigFlowResult | None:
        """Route to whatever Xiaomi is asking for next.

        A challenge can arrive in any order and more than once -- solving a
        captcha often leads to a verification, and confirming that verification
        can be met with a fresh captcha. Every step therefore defers here
        instead of assuming what follows it; assuming was what left the user
        stranded on a step that could not act on its own error.

        Returns None only when the answer belongs on the calling step itself.
        """
        if self._last_error == "captcha_required" and current != "captcha":
            return await self.async_step_captcha()
        if self._last_error == "code_required" and current != "code":
            return await self.async_step_code()
        return None

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

    async def _async_login(
        self, captcha_code: str | None = None, verify_code: str | None = None
    ) -> ConfigFlowResult | None:
        """Try the username/password login.

        Returns the next step, or None when the login did not complete -- the
        caller then re-renders its own form with `self._last_error`. It must not
        call a step itself: doing so returns a form the caller mistakes for
        success, and the user sees the dialog redraw with no explanation.
        """
        assert self._username is not None and self._password is not None
        cloud = self._async_cloud()
        try:
            if captcha_code is not None:
                await cloud.async_login_with_captcha(captcha_code)
            elif verify_code is not None:
                await cloud.async_login_with_verify(verify_code)
            else:
                await cloud.async_login(self._username, self._password)
        except CaptchaRequired as err:
            # Logged because a challenge is not a failure, and silence here
            # left nothing in the log to explain why sign-in kept looping.
            _LOGGER.debug("Xiaomi issued a captcha")
            self._captcha_image = err.image_data_uri
            self._last_error = "captcha_required"
            return None
        except CodeQuotaExhausted as err:
            _LOGGER.warning(
                "Xiaomi will not send another verification code: %s. "
                "Retrying keeps this alive; use the user ID and passToken route "
                "instead, which needs no code",
                err,
            )
            self._last_error = "code_quota"
            return None
        except VerificationRequired as err:
            _LOGGER.debug("Xiaomi sent a verification code to %s", err.destination)
            self._code_destination = err.destination
            self._last_error = "code_required"
            return None
        except XiaomiCloudError as err:
            _LOGGER.warning("Xiaomi sign-in failed: %s", err)
            self._last_error = "invalid_auth"
            return None
        return await self._async_after_login()

    async def _async_after_login(self) -> ConfigFlowResult:
        """Ask the cloud for gateways, then confirm their addresses on the LAN."""
        assert self._cloud is not None
        if self.source == SOURCE_REAUTH:
            return await self._async_finish_reauth()
        try:
            self._gateways = await self._cloud.async_find_gateways(self._country)
        except XiaomiCloudError as err:
            _LOGGER.warning(
                "Signed in, but could not list the account's devices: %s", err
            )
            return self.async_abort(reason="cannot_connect")

        if not self._gateways:
            _LOGGER.warning(
                "Signed in as %s, but region %r lists no EC2 gateway",
                self._cloud.user_id,
                self._country,
            )
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
        _LOGGER.info(
            "Gateway %s (%s): using %s (seen on the LAN: %s, cloud says: %s)",
            gateway.did,
            gateway.name,
            host or "no address",
            host if host and host != gateway.local_ip else "no",
            gateway.local_ip,
        )
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
                # silent gateway costs us the sensors, not the video. Find out
                # why, though, so the log can say more than "no response".
                diagnosis = await self.hass.async_add_executor_job(
                    client.diagnose, gateway.did
                )
                _LOGGER.warning(
                    "Gateway %s did not answer get_camera_list (%s); asking for "
                    "the camera MACs instead. Diagnosis: %s",
                    host,
                    err,
                    diagnosis,
                )
            else:
                cameras = [{"mac": cam.mac, "name": cam.name} for cam in found]

        if not cameras:
            # The gateway will not tell us locally; ask through the cloud,
            # which needs only the account we are already signed in with.
            cameras = await self._async_cameras_via_cloud(gateway)

        data = {
            CONF_GATEWAY_HOST: host,
            CONF_GATEWAY_DID: gateway.did,
            CONF_GATEWAY_TOKEN: gateway.token or "",
            CONF_USER_ID: self._cloud.user_id,
            CONF_PASS_TOKEN: self._cloud.pass_token,
            CONF_CAMERAS: cameras,
            CONF_COUNTRY: gateway.country or self._country,
        }
        if self._username and self._password:
            # Kept so an expired token renews itself. Without these, a rotation
            # means the cameras go dark until somebody signs in again by hand --
            # which is exactly the failure this integration exists to avoid.
            data[CONF_USERNAME] = self._username
            data[CONF_PASSWORD] = self._password

        title = gateway.name or f"EC2 gateway {host}"
        if not cameras:
            # The gateway did not answer, so we cannot know which cameras it
            # serves. Streaming does not need it to -- only their MACs -- so
            # ask for those rather than creating an entry with no cameras,
            # which could never set up.
            self._pending_title = title
            self._pending_data = data
            return await self.async_step_cameras()
        return self.async_create_entry(title=title, data=data)

    async def _async_cameras_via_cloud(
        self, gateway: CloudDevice
    ) -> list[dict[str, str]]:
        """`get_camera_list` relayed by the Xiaomi cloud; [] if that fails too."""
        assert self._cloud is not None
        try:
            result = await self._cloud.async_device_rpc(
                gateway.country or self._country, gateway.did, "get_camera_list"
            )
        except XiaomiCloudError as err:
            _LOGGER.warning(
                "The cloud could not list the cameras of gateway %s either: %s",
                gateway.did,
                err,
            )
            return []
        found = [
            CameraInfo.from_dict(item)
            for item in (result if isinstance(result, list) else [])
            if isinstance(item, dict) and item.get("mac")
        ]
        _LOGGER.warning(
            "Gateway %s listed %d camera(s) through the cloud: %s (raw reply: %s)",
            gateway.did,
            len(found),
            ", ".join(camera.mac for camera in found) or "none",
            str(result)[:500],
        )
        return [{"mac": camera.mac, "name": camera.name} for camera in found]

    async def async_step_cameras(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Take the camera MACs by hand."""
        errors: dict[str, str] = {}
        if user_input is not None:
            cameras = parse_cameras(user_input[CONF_MACS])
            if cameras is None:
                errors["base"] = "invalid_macs"
            else:
                return self.async_create_entry(
                    title=self._pending_title,
                    data={**self._pending_data, CONF_CAMERAS: cameras},
                )
        return self.async_show_form(
            step_id="cameras", data_schema=_macs_schema(), errors=errors
        )

    async def async_step_reconfigure(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Change which cameras an existing gateway entry streams."""
        entry = self._get_reconfigure_entry()
        errors: dict[str, str] = {}
        if user_input is not None:
            cameras = parse_cameras(user_input[CONF_MACS])
            if cameras is None:
                errors["base"] = "invalid_macs"
            else:
                return self.async_update_reload_and_abort(
                    entry, data={**entry.data, CONF_CAMERAS: cameras}
                )
        return self.async_show_form(
            step_id="reconfigure",
            data_schema=_macs_schema(format_cameras(entry.data.get(CONF_CAMERAS, []))),
            errors=errors,
        )

    _last_error: str = "invalid_auth"


def _port_of(listen: str) -> int | None:
    """The port in a `[host]:port` listen address, or None if it is not one."""
    host, sep, port = listen.strip().rpartition(":")
    if not sep or not port.isdigit() or " " in host:
        return None
    number = int(port)
    return number if 0 < number < 65536 else None


class Ec2OptionsFlow(OptionsFlow):
    """Ports for the bundled go2rtc.

    Needed whenever another go2rtc already runs on the host -- the go2rtc
    add-on, Frigate, WebRTC Camera -- because two cannot share a port, and the
    one that loses serves nothing.
    """

    async def async_step_init(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        errors: dict[str, str] = {}
        current = {
            CONF_RTSP_LISTEN: DEFAULT_RTSP_LISTEN,
            CONF_API_LISTEN: DEFAULT_API_LISTEN,
            CONF_WEBRTC_LISTEN: DEFAULT_WEBRTC_LISTEN,
            **self.config_entry.options,
        }
        if user_input is not None:
            ports = [_port_of(user_input[key]) for key in current]
            if None in ports:
                errors["base"] = "invalid_listen"
            elif len(set(ports)) != len(ports):
                errors["base"] = "duplicate_port"
            else:
                return self.async_create_entry(
                    data={key: user_input[key].strip() for key in current}
                )
            current.update(user_input)

        return self.async_show_form(
            step_id="init",
            data_schema=vol.Schema(
                {
                    vol.Required(key, default=current[key]): cv.string
                    for key in (CONF_RTSP_LISTEN, CONF_API_LISTEN, CONF_WEBRTC_LISTEN)
                }
            ),
            errors=errors,
        )
