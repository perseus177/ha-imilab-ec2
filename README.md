# IMILAB / Mijia EC2 cameras for Home Assistant

Home Assistant integration for **IMILAB / Mijia EC2** battery cameras
(`CMSXJ11A`) and their gateway (`chuangmi.gateway.ipc011`).

These cameras have **no RTSP and no ONVIF**. Video only ever leaves them over a
proprietary P2P protocol (TUTK) to their own gateway. This integration brings
them into Home Assistant as ordinary camera entities.

## How it works

Upstream [go2rtc](https://github.com/AlexxIT/go2rtc) cannot talk to this
hardware. The three things it was missing — the per-camera `mac` parameter, the
EC2 quality mapping and the `DecodeVideo` path — are in
[PR #2446](https://github.com/AlexxIT/go2rtc/pull/2446), which is not merged.

Rather than wait for that, this integration **ships its own pinned go2rtc build**
and runs it as a subprocess, the same way AlexxIT's *WebRTC Camera* integration
runs stock go2rtc. Consequences, all deliberate:

* upstream releases can never break you — the binary is pinned;
* nothing has to be merged for this to work;
* no hand-built binary in `/addons` that nobody can reproduce;
* works on Container and Core installs, not only on HAOS where add-ons exist.

The camera entity itself implements no video at all. Exactly like the Reolink
integration, it hands Home Assistant an RTSP URL and the `stream` component does
the rest.

## Installation

1. HACS → ⋮ → **Custom repositories** → add this repository, category
   **Integration**.
2. Install **IMILAB / Mijia EC2 cameras**, then restart Home Assistant.
3. **Settings → Devices & Services → Add Integration → IMILAB / Mijia EC2**.

## Configuration

| Field | Required | What it is |
|---|---|---|
| Gateway IP address | yes | The gateway on your LAN, e.g. `192.168.1.183` |
| Xiaomi user ID | yes | The numeric ID of the account that **owns** the cameras |
| Xiaomi passToken | yes | Cloud credential (`V1:…`) |
| Gateway miio token | no | 32 hex characters; unlocks discovery and sensors |

The gateway's device id is read during an unencrypted handshake, so you never
have to look up a `did`.

**The account must own the cameras.** An account they are merely *shared* with
gets `permit deny` from the cloud, because it is never issued P2P keys.

### Why the miio token is optional

Streaming needs only the account, the gateway address and each camera's MAC.
The miio token buys you camera auto-discovery and the battery/motion sensors.

Xiaomi rotates device tokens — an account migration will do it — and a stale
token must not stand between you and your video. So if the token is missing or
rejected, setup falls back to entering camera MACs by hand and streaming works
normally; only the sensors are unavailable.

Enter MACs as `B8DE5E4D1C25` or `B8DE5E4D1C25=Balcony`, comma or newline
separated.

## Streams and external players

Each camera gets three go2rtc streams. Quality names follow the **official app**,
not the `subtype` number, which is not monotonic:

| Stream | `subtype` | Resolution |
|---|---|---|
| `<mac>` | 0 | HD 1080p — the cap of this hardware |
| `<mac>_fluent` | 2 | 1080p, measurably the worst |
| `<mac>_low` | 1 | Speed 720p |

RTSP defaults to `:8554` **on every interface, on purpose**. External players —
Kodi via IPTV Simple, for example — pull these streams directly. Binding RTSP to
`127.0.0.1` silently breaks them.

Stream names are a contract. Renaming one breaks any playlist pointing at it.

Home Assistant bundles its own unpatched go2rtc on `127.0.0.1:18554`; the
defaults here do not collide with it.

## Things that are the hardware, not bugs

* **Cold start is roughly 16–20 seconds.** Waking a battery camera and
  negotiating P2P takes that long. Give anything consuming these streams a
  generous timeout.
* **The gateway serves one client at a time.** Connecting from Home Assistant
  will drop the phone app out of live view, and vice versa. Do not test in a
  loop.
* **Still images never wake the camera.** Home Assistant asks camera entities
  for thumbnails; answering those by opening a stream would flatten a 5100 mAh
  battery in days. This integration only ever returns a frame it already had.
* **Audio is PCM A-law**, which does not fit in MP4. Record to MKV, or
  transcode.

## Credits

The protocol work behind this — the captured command sequence, the `mac`
parameter, the quality mapping and the video decryption format — was done by
reverse-engineering the official app's own traffic and is offered upstream as
go2rtc PR #2446.
