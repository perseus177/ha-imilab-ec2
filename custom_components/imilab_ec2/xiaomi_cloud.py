"""Xiaomi account client.

A faithful port of the client in the Xiaomi Cloud Map Extractor
(`PiotrMachowski/Home-Assistant-custom-components-Xiaomi-Cloud-Map-Extractor`,
MIT), translated from `requests` to `aiohttp`. That implementation is known to
work against the live service; re-deriving it produced subtle differences that
broke two-factor sign-ins, so the sequence, the signing, and the header and
cookie sets here deliberately mirror it rather than improve on it.

Login:

    GET  /pass/serviceLogin?sid=xiaomiio&_json=true   -> _sign
    POST /pass/serviceLoginAuth2                      -> ssecurity + passToken
    GET  <location>                                   -> serviceToken cookie

Both account calls put their fields in the QUERY STRING, not the body.

Device discovery goes through the RC4-encrypted API: list the account's homes
(its own and the shared ones), then the devices in each. Responses carry a
`&&&START&&&` guard that has to be stripped before parsing.

Why any of this is needed: these cameras cannot stream without the cloud, since
every connection fetches fresh P2P keys from it. Having to authenticate anyway,
we let the cloud tell us where the gateways are, what their device ids are and
what their local miio tokens are, instead of asking a human to type them in.
"""

from __future__ import annotations

import base64
import hashlib
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
FORM_CT = "application/x-www-form-urlencoded"
TIMEOUT = 20

# Servers to sweep when we do not know where the account lives. "cn" is the
# bare host; every other one is a subdomain. The sweep stops as soon as a
# gateway turns up.
COUNTRIES = ("cn", "de", "us", "ru", "sg", "i2", "tw", "in")

GATEWAY_MODELS = {"chuangmi.gateway.ipc011"}


class XiaomiCloudError(Exception):
    """Login or an API call failed."""


class CaptchaRequired(XiaomiCloudError):
    """Xiaomi wants a captcha solved before it will accept the password.

    Reported as code 87001. It typically appears after a few failed sign-in
    attempts from the same address, and the Cloud Map Extractor does not handle
    it at all -- there is no upstream implementation to copy here.

    The image can only be fetched with the session that will submit the answer,
    because Xiaomi ties it to an `ick` cookie, so it has to be shown to the user
    rather than linked.
    """

    def __init__(self, image_data_uri: str) -> None:
        super().__init__("captcha required")
        self.image_data_uri = image_data_uri


class TwoFactorRequired(XiaomiCloudError):
    """Xiaomi wants verification before it will finish the login."""

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
    country: str

    @property
    def is_ec2_gateway(self) -> bool:
        return self.model in GATEWAY_MODELS


def api_host(country: str) -> str:
    """Base API URL for a country code."""
    prefix = "" if country == "cn" else f"{country}."
    return f"https://{prefix}api.io.mi.com/app"


def _to_json(text: str) -> Any:
    """Strip the guard and parse."""
    try:
        return json.loads(text.replace(JSON_GUARD, ""))
    except ValueError as err:
        raise XiaomiCloudError("unparseable response from Xiaomi") from err


def _rc4(key: bytes, payload: bytes) -> bytes:
    """RC4 with the first 1024 bytes of keystream discarded.

    Written out rather than pulling in pycryptodome, which Home Assistant does
    not guarantee is present. Matches `ARC4.new(key)` followed by encrypting
    1024 zero bytes before the real payload, which is what the original does.
    """
    state = list(range(256))
    j = 0
    for i in range(256):
        j = (j + state[i] + key[i % len(key)]) & 0xFF
        state[i], state[j] = state[j], state[i]

    i = j = 0

    def stream(length: int) -> bytearray:
        nonlocal i, j
        out = bytearray(length)
        for n in range(length):
            i = (i + 1) & 0xFF
            j = (j + state[i]) & 0xFF
            state[i], state[j] = state[j], state[i]
            out[n] = state[(state[i] + state[j]) & 0xFF]
        return out

    stream(1024)  # drop, exactly as ARC4.encrypt(bytes(1024)) does
    keystream = stream(len(payload))
    return bytes(a ^ b for a, b in zip(payload, keystream, strict=True))


def _encrypt_rc4(password: str, payload: str) -> str:
    return base64.b64encode(_rc4(base64.b64decode(password), payload.encode())).decode()


def _decrypt_rc4(password: str, payload: str) -> bytes:
    return _rc4(base64.b64decode(password), base64.b64decode(payload))


def _generate_agent() -> str:
    suffix = "".join(chr(65 + b % 5) for b in os.urandom(13))
    prefix = "".join(chr(97 + b % 26) for b in os.urandom(18))
    return f"{prefix}-{suffix} APP/com.xiaomi.mihome APPV/10.5.201"


def _generate_nonce(millis: int) -> str:
    return base64.b64encode(
        os.urandom(8) + int(millis / 60000).to_bytes(4, byteorder="big")
    ).decode()


def _enc_signature(url: str, method: str, signed_nonce: str, params: dict) -> str:
    parts = [method.upper(), url.split("com")[1].replace("/app/", "/")]
    parts.extend(f"{k}={v}" for k, v in params.items())
    parts.append(signed_nonce)
    return base64.b64encode(hashlib.sha1("&".join(parts).encode()).digest()).decode()


def _enc_params(
    url: str, method: str, signed_nonce: str, nonce: str, params: dict, ssecurity: str
) -> dict:
    params["rc4_hash__"] = _enc_signature(url, method, signed_nonce, params)
    for key, value in params.items():
        params[key] = _encrypt_rc4(signed_nonce, value)
    params.update(
        {
            "signature": _enc_signature(url, method, signed_nonce, params),
            "ssecurity": ssecurity,
            "_nonce": nonce,
        }
    )
    return params


class XiaomiCloud:
    """Minimal Xiaomi cloud client."""

    def __init__(self, session: aiohttp.ClientSession) -> None:
        self._session = session
        self._agent = _generate_agent()
        self._device_id = "".join(chr(97 + b % 26) for b in os.urandom(6))
        self.user_id: str | None = None
        self.c_user_id: str | None = None
        self.pass_token: str | None = None
        self.ssecurity: str | None = None
        self._service_token: str | None = None
        # Cached from the challenged attempt and reused on retry: the
        # verification URL is bound to the login context this identifies.
        self._sign: str | None = None
        # Set when a captcha is issued; the answer is only valid alongside it.
        self._ick: str | None = None

    @property
    def _account_cookies(self) -> dict[str, str]:
        cookies = {"sdkVersion": "accountsdk-18.8.15", "deviceId": self._device_id}
        if self._ick:
            cookies["ick"] = self._ick
        return cookies

    # -- login ---------------------------------------------------------------

    async def async_login(
        self, username: str, password: str, captcha_code: str | None = None
    ) -> None:
        """Log in with a username and password.

        Raises `TwoFactorRequired` when Xiaomi wants browser verification, or
        `CaptchaRequired` when it wants a captcha solved. Both retries must run
        on the SAME client: the sign, the device id and the captcha's `ick`
        cookie all belong to this login context.
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
        if captcha_code:
            fields["captCode"] = captcha_code

        data = await self._async_account_call(
            "POST", f"{ACCOUNT_BASE}/pass/serviceLoginAuth2", params=fields
        )
        try:
            await self._async_finish_login(data)
        except TwoFactorRequired:
            raise
        except XiaomiCloudError:
            self._sign = None
            raise
        self._sign = None

    async def async_login_with_token(self, user_id: str, pass_token: str) -> None:
        """Log in using a passToken -- no password, no verification."""
        data = await self._async_account_call(
            "GET",
            f"{ACCOUNT_BASE}/pass/serviceLogin?sid={SID}&_json=true",
            cookies={"userId": user_id, "passToken": pass_token},
        )
        await self._async_finish_login(data)

    async def _async_login_sign(self, username: str) -> str | None:
        data = await self._async_account_call(
            "GET",
            f"{ACCOUNT_BASE}/pass/serviceLogin?sid={SID}&_json=true",
            cookies={"userId": username},
        )
        return data.get("_sign")

    async def _async_finish_login(self, data: dict[str, Any]) -> None:
        ssecurity = data.get("ssecurity")
        if not ssecurity or len(str(ssecurity)) <= 4:
            notification = data.get("notificationUrl")
            if notification:
                raise TwoFactorRequired(notification)
            captcha_url = data.get("captchaUrl")
            if captcha_url:
                raise CaptchaRequired(await self._async_fetch_captcha(captcha_url))
            _LOGGER.debug(
                "serviceLogin refused us: %s",
                {
                    k: v
                    for k, v in data.items()
                    if k not in ("passToken", "ssecurity", "location")
                },
            )
            desc = data.get("desc") or data.get("description") or "login rejected"
            raise XiaomiCloudError(f"{desc} (code {data.get('code')})")

        self.ssecurity = ssecurity
        self.user_id = str(data.get("userId") or "")
        self.c_user_id = data.get("cUserId")
        self.pass_token = data.get("passToken")

        location = data.get("location")
        if not location:
            raise XiaomiCloudError("login response carried no location")

        # Following the location is what mints the serviceToken cookie.
        try:
            async with self._session.get(
                location,
                headers={"User-Agent": self._agent, "Content-Type": FORM_CT},
                timeout=aiohttp.ClientTimeout(total=TIMEOUT),
            ) as response:
                token = response.cookies.get("serviceToken")
                self._service_token = token.value if token else None
        except aiohttp.ClientError as err:
            raise XiaomiCloudError(f"could not complete login: {err}") from err

        if not self._service_token:
            raise XiaomiCloudError("login did not yield a serviceToken")

    async def _async_fetch_captcha(self, captcha_url: str) -> str:
        """Fetch the captcha image and return it as a data URI.

        The response sets an `ick` cookie that the answer is checked against,
        so it is kept and replayed on the retry.
        """
        url = captcha_url
        if url.startswith("/"):
            url = ACCOUNT_BASE + url
        try:
            async with self._session.get(
                url,
                headers={"User-Agent": self._agent},
                cookies=self._account_cookies,
                timeout=aiohttp.ClientTimeout(total=TIMEOUT),
            ) as response:
                if response.status != 200:
                    raise XiaomiCloudError(f"captcha image: HTTP {response.status}")
                ick = response.cookies.get("ick")
                if ick:
                    self._ick = ick.value
                payload = await response.read()
                content_type = response.headers.get("Content-Type", "image/jpeg")
        except aiohttp.ClientError as err:
            raise XiaomiCloudError(f"captcha image: {err}") from err

        encoded = base64.b64encode(payload).decode()
        return f"data:{content_type.split(';')[0]};base64,{encoded}"

    async def _async_account_call(
        self,
        method: str,
        url: str,
        params: dict[str, str] | None = None,
        cookies: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        """One account-service call. Fields go in the query string, both verbs."""
        try:
            async with self._session.request(
                method,
                url,
                params=params,
                headers={"User-Agent": self._agent, "Content-Type": FORM_CT},
                cookies={**self._account_cookies, **(cookies or {})},
                timeout=aiohttp.ClientTimeout(total=TIMEOUT),
            ) as response:
                text = await response.text()
        except aiohttp.ClientError as err:
            raise XiaomiCloudError(f"{url}: {err}") from err

        parsed = _to_json(text)
        if not isinstance(parsed, dict):
            raise XiaomiCloudError("unexpected response from the account service")
        return parsed

    # -- encrypted API -------------------------------------------------------

    def _signed_nonce(self, nonce: str) -> str:
        digest = hashlib.sha256(
            base64.b64decode(self.ssecurity or "") + base64.b64decode(nonce)
        )
        return base64.b64encode(digest.digest()).decode()

    async def _async_api(self, url: str, params: dict[str, str]) -> Any:
        """RC4-encrypted API call, the way the Mi Home app makes them."""
        if not (self.ssecurity and self.user_id and self._service_token):
            raise XiaomiCloudError("not logged in")

        nonce = _generate_nonce(round(time.time() * 1000))
        signed = self._signed_nonce(nonce)
        fields = _enc_params(url, "POST", signed, nonce, dict(params), self.ssecurity)

        headers = {
            "Accept-Encoding": "identity",
            "User-Agent": self._agent,
            "Content-Type": FORM_CT,
            "x-xiaomi-protocal-flag-cli": "PROTOCAL-HTTP2",
            "MIOT-ENCRYPT-ALGORITHM": "ENCRYPT-RC4",
        }
        cookies = {
            "userId": str(self.user_id),
            "yetAnotherServiceToken": str(self._service_token),
            "serviceToken": str(self._service_token),
            "locale": "en_GB",
            "timezone": "GMT+02:00",
            "is_daylight": "1",
            "dst_offset": "3600000",
            "channel": "MI_APP_STORE",
        }

        try:
            async with self._session.post(
                url,
                params=fields,
                headers=headers,
                cookies=cookies,
                timeout=aiohttp.ClientTimeout(total=TIMEOUT),
            ) as response:
                if response.status != 200:
                    raise XiaomiCloudError(f"{url}: HTTP {response.status}")
                text = await response.text()
        except aiohttp.ClientError as err:
            raise XiaomiCloudError(f"{url}: {err}") from err

        decoded = _decrypt_rc4(self._signed_nonce(fields["_nonce"]), text)
        return json.loads(decoded)

    # -- discovery -----------------------------------------------------------

    async def _async_homes(self, country: str) -> list[tuple[int, str]]:
        """(home_id, owner_id) for the account's own and shared homes."""
        url = api_host(country) + "/v2/homeroom/gethome"
        params = {
            "data": json.dumps(
                {
                    "fg": True,
                    "fetch_share": True,
                    "fetch_share_dev": True,
                    "limit": 300,
                    "app_ver": 7,
                }
            )
        }
        result = (await self._async_api(url, params) or {}).get("result") or {}
        homes: list[tuple[int, str]] = []
        for key in ("homelist", "share_home_list"):
            for home in result.get(key) or []:
                homes.append((int(home["id"]), home["uid"]))
        return homes

    async def _async_devices_in_home(
        self, country: str, home_id: int, owner_id: str
    ) -> list[CloudDevice]:
        url = api_host(country) + "/v2/home/home_device_list"
        params = {
            "data": json.dumps(
                {
                    "home_id": home_id,
                    "home_owner": owner_id,
                    "limit": 200,
                    "get_split_device": True,
                    "support_smart_home": True,
                }
            )
        }
        result = (await self._async_api(url, params) or {}).get("result") or {}
        return [
            CloudDevice(
                did=str(device.get("did", "")),
                name=str(device.get("name", "")),
                model=str(device.get("model", "")),
                local_ip=device.get("localip") or None,
                token=device.get("token") or None,
                country=country,
            )
            for device in result.get("device_info") or []
            if isinstance(device, dict)
        ]

    async def async_find_gateways(
        self, country: str | None = None
    ) -> list[CloudDevice]:
        """EC2 gateways on the account, sweeping servers until some turn up.

        Which server an account lives on is not knowable in advance -- asking
        the wrong one answers with an empty list rather than an error -- so each
        is tried in turn and the sweep stops at the first that yields a gateway.
        """
        found: dict[str, CloudDevice] = {}
        # An explicit choice is honoured; otherwise sweep every server.
        candidates = (country,) if country else COUNTRIES
        for server in candidates:
            try:
                homes = await self._async_homes(server)
            except (XiaomiCloudError, ValueError, KeyError, TypeError) as err:
                _LOGGER.debug("gethome failed for %r: %s", server, err)
                continue
            for home_id, owner_id in homes:
                try:
                    devices = await self._async_devices_in_home(
                        server, home_id, owner_id
                    )
                except (XiaomiCloudError, ValueError, KeyError, TypeError) as err:
                    _LOGGER.debug("home_device_list failed for %r: %s", server, err)
                    continue
                for device in devices:
                    if device.is_ec2_gateway:
                        found.setdefault(device.did, device)
            if found:
                break
        return list(found.values())


__all__ = [
    "CloudDevice",
    "TwoFactorRequired",
    "XiaomiCloud",
    "XiaomiCloudError",
    "api_host",
]
