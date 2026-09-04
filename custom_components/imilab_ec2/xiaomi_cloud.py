"""Xiaomi account client: log in, then ask which devices the account owns.

Why this exists at all: these cameras cannot stream without the cloud. Every
connection fetches fresh P2P keys from `/device/devicepass`, so an account
credential is mandatory. Once we are talking to the cloud anyway, it will also
tell us every gateway on the account -- its address, its device id and its local
miio token -- which is far better than asking a human to type them in.

The login is the standard Xiaomi `serviceLogin` dance:

    GET  /pass/serviceLogin            -> _sign
    POST /pass/serviceLoginAuth2       -> ssecurity + passToken, or a 2FA demand
    GET  <location>                    -> serviceToken cookie
    POST /app/home/device_list         -> the devices

Responses are prefixed with a `&&&START&&&` guard that has to be stripped before
parsing.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import time
from dataclasses import dataclass
from typing import Any

import aiohttp

_LOGGER = logging.getLogger(__name__)

ACCOUNT_BASE = "https://account.xiaomi.com"
STS_CALLBACK = "https://sts.api.io.mi.com/sts"
JSON_GUARD = "&&&START&&&"
SID = "xiaomiio"
TIMEOUT = 20
ACCOUNT_HEADERS_CT = "application/x-www-form-urlencoded"

# Only these regions have their own API host. Everything else -- including
# mainland China, and including an empty region -- lives on the bare host.
REGION_HOSTS = {"de", "i2", "ru", "sg", "us"}

GATEWAY_MODELS = {"chuangmi.gateway.ipc011"}


class XiaomiCloudError(Exception):
    """Login or an API call failed."""


class TwoFactorRequired(XiaomiCloudError):
    """Xiaomi wants a verification code before it will finish the login."""

    def __init__(self, notification_url: str) -> None:
        super().__init__("two-factor verification required")
        self.notification_url = notification_url


@dataclass(frozen=True)
class CloudDevice:
    """One device as the account sees it."""

    did: str
    name: str
    model: str
    local_ip: str | None
    token: str | None
    mac: str | None

    @property
    def is_ec2_gateway(self) -> bool:
        return self.model in GATEWAY_MODELS


def api_host(region: str | None) -> str:
    """Map a region to its API host."""
    if region and region.lower() in REGION_HOSTS:
        return f"https://{region.lower()}.api.io.mi.com/app"
    return "https://api.io.mi.com/app"


def _strip_guard(text: str) -> Any:
    text = text.removeprefix(JSON_GUARD)
    try:
        return json.loads(text)
    except ValueError as err:
        raise XiaomiCloudError("unparseable response from Xiaomi") from err


class XiaomiCloud:
    """Minimal Xiaomi cloud client."""

    def __init__(self, session: aiohttp.ClientSession) -> None:
        self._session = session
        # Six lowercase letters, the shape Xiaomi's own SDK uses. It must stay
        # STABLE for the life of this client: a completed two-factor
        # verification is bound to this device id, so regenerating it on a
        # retry makes the account look like a new device and the verification
        # the user just did counts for nothing.
        self._device_id = "".join(chr(97 + b % 26) for b in os.urandom(6))
        self._agent = _generate_agent()
        self.user_id: str | None = None
        self.pass_token: str | None = None
        self.ssecurity: str | None = None
        self._service_token: str | None = None
        # Cached from the first attempt and reused on retries. The
        # verification URL Xiaomi hands back is bound to the login context this
        # sign identifies, so fetching a fresh one for the retry would start a
        # new context that knows nothing about the verification the user just
        # completed.
        self._sign: str | None = None

    @property
    def _base_cookies(self) -> dict[str, str]:
        """Cookies every account request carries."""
        return {
            "sdkVersion": "accountsdk-18.8.15",
            "deviceId": self._device_id,
        }

    # -- login ---------------------------------------------------------------

    async def async_login(self, username: str, password: str) -> None:
        """Log in with a username and password.

        A faithful port of the sequence the Xiaomi Cloud Map Extractor uses,
        because re-deriving it produced subtle differences that broke
        two-factor accounts. In particular serviceLoginAuth2 takes its fields
        in the QUERY STRING, not the request body.

        Raises `TwoFactorRequired` when Xiaomi wants verification. Once the
        user has completed it in a browser, call this again on the SAME client:
        the sign, device id and cookie jar all have to match the attempt that
        was challenged.
        """
        if self._sign is None:
            self._sign = await self._async_login_sign(username)

        fields = {
            "sid": SID,
            "hash": hashlib.md5(password.encode()).hexdigest().upper(),
            "callback": STS_CALLBACK,
            "qs": "%3Fsid%3Dxiaomiio%26_json%3Dtrue",
            "user": username,
            "_json": "true",
        }
        if self._sign:
            fields["_sign"] = self._sign

        data = await self._async_request(
            "POST", f"{ACCOUNT_BASE}/pass/serviceLoginAuth2", params=fields
        )
        try:
            await self._async_finish_login(data)
        except TwoFactorRequired:
            # Keep the sign: the verification the user is about to do belongs
            # to this context, and the retry has to come back to it.
            raise
        except XiaomiCloudError:
            self._sign = None
            raise
        self._sign = None

    async def async_login_with_token(self, user_id: str, pass_token: str) -> None:
        """Log in using a passToken -- no password, no verification code.

        This is the same path go2rtc uses, and the reason a working setup keeps
        working without ever storing a password.
        """
        data = await self._async_request(
            "GET",
            f"{ACCOUNT_BASE}/pass/serviceLogin?sid={SID}&_json=true",
            cookies={"userId": user_id, "passToken": pass_token},
        )
        await self._async_finish_login(data)

    async def _async_login_sign(self, username: str | None = None) -> str | None:
        """Fetch the `_sign` nonce that serviceLoginAuth2 wants."""
        cookies = {"userId": username} if username else None
        data = await self._async_request(
            "GET",
            f"{ACCOUNT_BASE}/pass/serviceLogin?sid={SID}&_json=true",
            cookies=cookies,
        )
        return data.get("_sign")

    async def _async_finish_login(self, data: dict[str, Any]) -> None:
        """Consume a serviceLogin response and pick up the session."""
        if not data.get("ssecurity"):
            notification = data.get("notificationUrl")
            if notification:
                # Account is protected by 2FA. The caller has to send the user
                # through the verification page before we can continue.
                raise TwoFactorRequired(notification)
            code = data.get("code")
            desc = data.get("desc") or data.get("description") or "login rejected"
            _LOGGER.debug(
                "serviceLogin refused us: %s",
                {
                    k: v
                    for k, v in data.items()
                    if k not in ("passToken", "ssecurity", "location")
                },
            )
            raise XiaomiCloudError(f"{desc} (code {code})")

        self.ssecurity = data["ssecurity"]
        self.user_id = str(data.get("userId") or "")
        self.pass_token = data.get("passToken")

        location = data.get("location")
        if not location:
            raise XiaomiCloudError("login response carried no location")

        # Following the location is what mints the serviceToken cookie.
        try:
            async with self._session.get(
                location,
                timeout=aiohttp.ClientTimeout(total=TIMEOUT),
                allow_redirects=True,
            ) as response:
                for cookie in response.cookies.values():
                    if cookie.key == "serviceToken":
                        self._service_token = cookie.value
                if self._service_token is None:
                    filtered = self._session.cookie_jar.filter_cookies(
                        aiohttp.helpers.URL(location)
                    )
                    token = filtered.get("serviceToken")
                    self._service_token = token.value if token else None
        except aiohttp.ClientError as err:
            raise XiaomiCloudError(f"could not complete login: {err}") from err

        if not self._service_token:
            raise XiaomiCloudError("login did not yield a serviceToken")

    # -- signed API ----------------------------------------------------------

    async def async_device_list(self, region: str | None = None) -> list[CloudDevice]:
        """Every device on the account, in one call."""
        payload = json.dumps(
            {"getVirtualModel": False, "getHuamiDevices": 0}, separators=(",", ":")
        )
        result = await self._async_signed_post("/home/device_list", payload, region)
        devices = (result or {}).get("list") or []
        return [
            CloudDevice(
                did=str(item.get("did", "")),
                name=str(item.get("name", "")),
                model=str(item.get("model", "")),
                local_ip=item.get("localip") or None,
                token=item.get("token") or None,
                mac=item.get("mac") or None,
            )
            for item in devices
            if isinstance(item, dict)
        ]

    async def async_find_gateways(self) -> list[CloudDevice]:
        """EC2 gateways on the account, trying every plausible region.

        The owning account here sits in the default (mainland China) region,
        where the region string is empty -- not `de`. Asking the wrong host
        returns an empty list rather than an error, so all of them get a turn.
        """
        seen: dict[str, CloudDevice] = {}
        for region in ("", *sorted(REGION_HOSTS)):
            try:
                devices = await self.async_device_list(region or None)
            except XiaomiCloudError as err:
                _LOGGER.debug("device_list failed for region %r: %s", region, err)
                continue
            for device in devices:
                if device.is_ec2_gateway and device.did not in seen:
                    seen[device.did] = device
            if seen:
                # Found them; no need to keep sweeping regions.
                break
        return list(seen.values())

    async def _async_signed_post(
        self, path: str, data: str, region: str | None
    ) -> dict[str, Any]:
        if not self.ssecurity or not self.user_id or not self._service_token:
            raise XiaomiCloudError("not logged in")

        nonce = _gen_nonce()
        signed = _signed_nonce(self.ssecurity, nonce)
        signature = _sign(path, signed, nonce, data)

        url = api_host(region) + path
        headers = {
            "User-Agent": self._agent,
            "x-xiaomi-protocal-flag-cli": "PROTOCAL-HTTP2",
            "Content-Type": "application/x-www-form-urlencoded",
        }
        cookies = {
            "userId": self.user_id,
            "serviceToken": self._service_token,
            "locale": "en_GB",
        }
        form = {"signature": signature, "_nonce": nonce, "data": data}

        try:
            async with self._session.post(
                url,
                data=form,
                headers=headers,
                cookies=cookies,
                timeout=aiohttp.ClientTimeout(total=TIMEOUT),
            ) as response:
                text = await response.text()
        except aiohttp.ClientError as err:
            raise XiaomiCloudError(f"{path}: {err}") from err

        parsed = _strip_guard(text)
        if not isinstance(parsed, dict):
            raise XiaomiCloudError(f"{path}: unexpected response")
        return parsed.get("result") or {}

    # -- plumbing ------------------------------------------------------------

    async def _async_request(
        self,
        method: str,
        url: str,
        params: dict[str, str] | None = None,
        cookies: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        """One account-service call, returning the guarded JSON body.

        Fields go in the query string for both verbs -- that is what Xiaomi's
        account service expects, and sending them as a form body is what broke
        two-factor logins here.
        """
        headers = {"User-Agent": self._agent, "Content-Type": ACCOUNT_HEADERS_CT}
        jar = {**self._base_cookies, **(cookies or {})}
        try:
            async with self._session.request(
                method,
                url,
                params=params,
                headers=headers,
                cookies=jar,
                timeout=aiohttp.ClientTimeout(total=TIMEOUT),
            ) as response:
                text = await response.text()
        except aiohttp.ClientError as err:
            raise XiaomiCloudError(f"{url}: {err}") from err

        parsed = _strip_guard(text)
        if not isinstance(parsed, dict):
            raise XiaomiCloudError("unexpected response from the account service")
        return parsed


def _generate_agent() -> str:
    """The user agent shape Xiaomi's own account SDK sends."""
    suffix = "".join(chr(65 + b % 5) for b in os.urandom(13))
    prefix = "".join(chr(97 + b % 26) for b in os.urandom(18))
    return f"{prefix}-{suffix} APP/com.xiaomi.mihome APPV/10.5.201"


def _gen_nonce() -> str:
    return base64.b64encode(
        os.urandom(8) + int(time.time() / 60).to_bytes(4, "big")
    ).decode()


def _signed_nonce(ssecurity: str, nonce: str) -> str:
    digest = hashlib.sha256(base64.b64decode(ssecurity) + base64.b64decode(nonce))
    return base64.b64encode(digest.digest()).decode()


def _sign(path: str, signed: str, nonce: str, data: str) -> str:
    message = "&".join([path, signed, nonce, f"data={data}"])
    mac = hmac.new(base64.b64decode(signed), message.encode(), hashlib.sha256)
    return base64.b64encode(mac.digest()).decode()
