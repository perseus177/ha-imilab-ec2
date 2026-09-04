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


class VerificationRequired(XiaomiCloudError):
    """Xiaomi has sent a code by email or SMS and is waiting for it.

    The code is already on its way by the time this is raised: unlike sending
    the user off to a web page, the verification is driven from here, so the
    only thing left is to type in what arrived.
    """

    def __init__(self, masked_phone: str, masked_email: str) -> None:
        super().__init__("verification code required")
        self.masked_phone = masked_phone
        self.masked_email = masked_email

    @property
    def destination(self) -> str:
        """Where the code went, as Xiaomi masks it."""
        return self.masked_email or self.masked_phone or "your registered contact"


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


def _image_mime(payload: bytes) -> str:
    """Sniff an image type; Xiaomi's own Content-Type is not usable."""
    if payload[:3] == bytes((0xFF, 0xD8, 0xFF)):
        return "image/jpeg"
    if payload[:4] == bytes((0x89, 0x50, 0x4E, 0x47)):
        return "image/png"
    if payload[:4] == b"GIF8":
        return "image/gif"
    return "image/jpeg"


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
        alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        self._device_id = "".join(alphabet[b % len(alphabet)] for b in os.urandom(16))
        self.user_id: str | None = None
        self.c_user_id: str | None = None
        self.pass_token: str | None = None
        self.ssecurity: str | None = None
        self._service_token: str | None = None
        # Carries state across a challenged sign-in: credentials, the
        # captcha's ick cookie, and the verification flag and session. Mirrors
        # the auth map go2rtc keeps for exactly the same reason.
        self._auth: dict[str, str] = {}

    # -- login ---------------------------------------------------------------
    #
    # Ported from go2rtc's pkg/xiaomi/cloud.go, which completes a challenged
    # sign-in entirely in-process: it starts the verification itself, has
    # Xiaomi send the code, and submits it. No browser is involved, which is
    # why the same account signs in there on the first attempt.

    async def async_login(self, username: str, password: str) -> None:
        """Sign in. Raises CaptchaRequired or VerificationRequired to continue."""
        self._auth["username"] = username
        self._auth["password"] = password
        await self._async_login_step()

    async def async_login_with_captcha(self, code: str) -> None:
        """Answer a captcha and carry on from wherever it interrupted."""
        self._auth["captcha_code"] = code
        if self._auth.get("flag"):
            # The captcha interrupted the verification, not the password.
            await self._async_send_ticket()
            return
        await self._async_login_step()

    async def async_login_with_verify(self, ticket: str) -> None:
        """Submit the code Xiaomi sent by email or SMS."""
        flag = self._auth.get("flag")
        if not flag:
            raise XiaomiCloudError("no verification in progress")
        name = self._verify_name()
        # go2rtc builds this parameter without an "=" and Xiaomi accepts it.
        # Kept identical rather than tidied: this is the form known to work.
        params = f"_flag{flag}&ticket={ticket}&trust=false&_json=true"
        data = await self._async_raw(
            "POST",
            f"{ACCOUNT_BASE}/identity/auth/verify{name}?{params}",
            cookies=f"identity_session={self._auth.get('identity_session', '')}",
        )
        location = data.get("location")
        if not location:
            raise XiaomiCloudError(
                f"verification rejected: {data.get('desc') or data.get('code')}"
            )
        await self._async_finish(location)

    async def _async_login_step(self) -> None:
        first = await self._async_raw(
            "GET", f"{ACCOUNT_BASE}/pass/serviceLogin?_json=true&sid={SID}"
        )
        # sid, callback and qs are taken from this response. Hardcoding them is
        # one of the ways a hand-rolled client drifts from the real one.
        digest = hashlib.md5(self._auth["password"].encode()).hexdigest()
        form = {
            "_json": "true",
            "hash": digest.upper(),
            "sid": first.get("sid", SID),
            "callback": first.get("callback", STS_CALLBACK),
            "_sign": first.get("_sign", ""),
            "qs": first.get("qs", ""),
            "user": self._auth["username"],
        }
        cookies = f"deviceId={self._device_id}"
        if self._auth.get("captcha_code"):
            form["captCode"] = self._auth["captcha_code"]
            cookies += f"; ick={self._auth.get('ick', '')}"

        data = await self._async_raw(
            "POST",
            f"{ACCOUNT_BASE}/pass/serviceLoginAuth2",
            form=form,
            cookies=cookies,
        )

        captcha = data.get("captchaUrl") or data.get("captchaURL")
        if captcha:
            await self._async_get_captcha(captcha)
        notification = data.get("notificationUrl")
        if notification:
            await self._async_auth_start(notification)

        location = data.get("location")
        if not location:
            _LOGGER.debug(
                "serviceLogin refused us: %s",
                {k: v for k, v in data.items() if k not in ("passToken", "ssecurity")},
            )
            desc = data.get("desc") or data.get("description") or "sign-in rejected"
            raise XiaomiCloudError(f"{desc} (code {data.get('code')})")

        self._auth.clear()
        self.ssecurity = data.get("ssecurity")
        self.pass_token = data.get("passToken")
        await self._async_finish(location)

    async def _async_get_captcha(self, captcha_url: str) -> None:
        """Fetch the captcha image and hand it up; the ick cookie is kept."""
        url = captcha_url
        if url.startswith("/"):
            url = ACCOUNT_BASE + url
        try:
            async with self._session.get(
                url,
                headers={
                    "User-Agent": self._agent,
                    "Cookie": f"deviceId={self._device_id}",
                },
                timeout=aiohttp.ClientTimeout(total=TIMEOUT),
            ) as response:
                payload = await response.read()
                ick = response.cookies.get("ick")
                if ick:
                    self._auth["ick"] = ick.value
        except aiohttp.ClientError as err:
            raise XiaomiCloudError(f"captcha image: {err}") from err

        # Xiaomi serves this as application/octet-stream, so the type comes
        # from the magic bytes rather than the header.
        encoded = base64.b64encode(payload).decode()
        raise CaptchaRequired(f"data:{_image_mime(payload)};base64,{encoded}")

    async def _async_auth_start(self, notification_url: str) -> None:
        """Begin verification and have Xiaomi send the code."""
        url = notification_url.replace(
            "/fe/service/identity/authStart", "/identity/list", 1
        )
        data, jar = await self._async_raw_with_cookies("GET", url)
        self._auth["flag"] = str(data.get("flag", ""))
        session = jar.get("identity_session")
        if session:
            self._auth["identity_session"] = session.value
        await self._async_send_ticket()

    def _verify_name(self) -> str:
        return {"4": "Phone", "8": "Email"}.get(self._auth.get("flag", ""), "")

    async def _async_send_ticket(self) -> None:
        """Ask Xiaomi to send the code, then report where it went."""
        name = self._verify_name()
        flag = self._auth.get("flag", "")
        cookies = f"identity_session={self._auth.get('identity_session', '')}"

        info = await self._async_raw(
            "GET",
            f"{ACCOUNT_BASE}/identity/auth/verify{name}?_flag={flag}&_json=true",
            cookies=cookies,
        )

        send_cookies = cookies
        captcha_code = self._auth.get("captcha_code", "")
        if captcha_code:
            send_cookies += f"; ick={self._auth.get('ick', '')}"

        sent = await self._async_raw(
            "POST",
            f"{ACCOUNT_BASE}/identity/auth/send{name}Ticket",
            form={"_json": "true", "icode": captcha_code, "retry": "0"},
            cookies=send_cookies,
        )

        captcha = sent.get("captchaUrl") or sent.get("captchaURL")
        if captcha:
            await self._async_get_captcha(captcha)
        if sent.get("code") not in (0, None):
            raise XiaomiCloudError(
                f"could not send the code: {sent.get('desc') or sent}"
            )

        raise VerificationRequired(
            info.get("maskedPhone") or "", info.get("maskedEmail") or ""
        )

    async def async_login_with_token(self, user_id: str, pass_token: str) -> None:
        """Sign in using a passToken -- no password, no challenge."""
        data = await self._async_raw(
            "GET",
            f"{ACCOUNT_BASE}/pass/serviceLogin?_json=true&sid={SID}",
            cookies=f"userId={user_id}; passToken={pass_token}",
        )
        location = data.get("location")
        if not location:
            raise XiaomiCloudError("passToken rejected")
        self.ssecurity = data.get("ssecurity")
        self.pass_token = data.get("passToken") or pass_token
        self.user_id = user_id
        await self._async_finish(location)

    async def _async_finish(self, location: str) -> None:
        """Follow the callback; this is what mints userId and serviceToken."""
        try:
            async with self._session.get(
                location,
                headers={"User-Agent": self._agent},
                timeout=aiohttp.ClientTimeout(total=TIMEOUT),
            ) as response:
                for name, cookie in response.cookies.items():
                    if name == "userId":
                        self.user_id = cookie.value
                    elif name == "cUserId":
                        self.c_user_id = cookie.value
                    elif name == "serviceToken":
                        self._service_token = cookie.value
                    elif name == "passToken":
                        self.pass_token = cookie.value
                pragma = response.headers.get("Extension-Pragma")
                if pragma:
                    try:
                        self.ssecurity = json.loads(pragma).get(
                            "ssecurity", self.ssecurity
                        )
                    except ValueError:
                        pass
        except aiohttp.ClientError as err:
            raise XiaomiCloudError(f"could not complete sign-in: {err}") from err

        if not self._service_token:
            raise XiaomiCloudError("sign-in did not yield a serviceToken")

    async def _async_raw(
        self,
        method: str,
        url: str,
        form: dict[str, str] | None = None,
        cookies: str | None = None,
    ) -> dict[str, Any]:
        data, _ = await self._async_raw_with_cookies(method, url, form, cookies)
        return data

    async def _async_raw_with_cookies(
        self,
        method: str,
        url: str,
        form: dict[str, str] | None = None,
        cookies: str | None = None,
    ) -> tuple[dict[str, Any], Any]:
        """One account call. The form goes in the BODY, as go2rtc sends it."""
        headers = {"User-Agent": self._agent}
        if cookies:
            headers["Cookie"] = cookies
        try:
            async with self._session.request(
                method,
                url,
                data=form,
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=TIMEOUT),
            ) as response:
                text = await response.text()
                jar = response.cookies
        except aiohttp.ClientError as err:
            raise XiaomiCloudError(f"{url}: {err}") from err

        if not text.startswith(JSON_GUARD):
            raise XiaomiCloudError(f"unexpected response: {text[:200]}")
        try:
            parsed = json.loads(text[len(JSON_GUARD) :])
        except ValueError as err:
            raise XiaomiCloudError("unparseable response from Xiaomi") from err
        if not isinstance(parsed, dict):
            raise XiaomiCloudError("unexpected response shape")
        return parsed, jar

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
    "VerificationRequired",
    "XiaomiCloud",
    "XiaomiCloudError",
    "api_host",
]
