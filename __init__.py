"""browser-health — report the state of the local CDP browser stack.

Diagnosis only. This plugin never navigates, never reads cookie *values*, and
never writes to a profile: it opens the cookie database read-only+immutable, so a
running Chrome cannot be locked by it.

What it answers, in one call:

* is the CDP profile browser on :9222 alive, and is it the *visible* Chrome or a
  headless impostor that stole the port?
* how many live cookies does the profile hold? (a near-empty store is a wiped
  login, not a healthy session)
* is the agent browser on :9223 up? (the two must not be confused — see the
  watchdog bug where one killed the other)
* one verdict: ``ok`` / ``degraded`` / ``down``, with the reasons spelled out.
"""

from __future__ import annotations

import json
import os
import sqlite3
import urllib.request
from pathlib import Path
from typing import Any, Dict

PROFILE_PORT = 9222
AGENT_PORT = 9223

# A profile below this many cookies has lost its logins in practice; the store
# ages out (~30 days) and a "restore" into a live profile is how sessions die.
MIN_HEALTHY_COOKIES = 50


def _openamer_home() -> Path:
    env = os.environ.get("OPENAMER_HOME")
    if env:
        return Path(env)
    return Path.home() / "AppData" / "Local" / "openamer-laptop"


def _get_json(port: int, path: str, timeout: float = 3.0) -> Any | None:
    url = f"http://127.0.0.1:{int(port)}{path}"
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except Exception:
        return None


def _ws_url(port: int) -> str | None:
    pages = _pages(port)
    return pages[0].get("webSocketDebuggerUrl") if pages else None


def _cdp_call(ws_url: str, method: str, params: Dict[str, Any] | None = None,
              timeout: float = 15.0) -> Dict[str, Any] | None:
    """One CDP command over a minimal stdlib WebSocket client.

    Deliberately dependency-free: ``websocket-client`` is not installed in every
    OpenAmer runtime (the agent venv does not ship it), and a health plugin that
    quietly reports "unreadable" because of an absent package is worse than
    useless. Only what CDP needs: no extensions, no fragmentation, no TLS.
    """
    import base64
    import os as _os
    import socket
    import struct
    from urllib.parse import urlparse

    parsed = urlparse(ws_url)
    host = parsed.hostname or "127.0.0.1"
    port = parsed.port or 80
    path = (parsed.path or "/") + (f"?{parsed.query}" if parsed.query else "")

    key = base64.b64encode(_os.urandom(16)).decode("ascii")
    handshake = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}:{port}\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {key}\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        f"Origin: http://{host}:{port}\r\n\r\n"
    )

    try:
        sock = socket.create_connection((host, port), timeout=timeout)
    except OSError:
        return None

    try:
        sock.sendall(handshake.encode("ascii"))
        buf = b""
        while b"\r\n\r\n" not in buf:
            chunk = sock.recv(4096)
            if not chunk:
                return None
            buf += chunk
        head, _, buf = buf.partition(b"\r\n\r\n")
        status_line = head.split(b"\r\n", 1)[0]
        if b"101" not in status_line:
            return None

        message = json.dumps({"id": 1, "method": method, "params": params or {}}).encode()
        mask = _os.urandom(4)
        masked = bytes(b ^ mask[i % 4] for i, b in enumerate(message))
        size = len(message)
        if size < 126:
            header = struct.pack("!BB", 0x81, 0x80 | size)
        elif size < 65536:
            header = struct.pack("!BBH", 0x81, 0x80 | 126, size)
        else:
            header = struct.pack("!BBQ", 0x81, 0x80 | 127, size)
        sock.sendall(header + mask + masked)

        for _ in range(200):
            while len(buf) < 2:
                chunk = sock.recv(65536)
                if not chunk:
                    return None
                buf += chunk
            first, second = buf[0], buf[1]
            index = 2
            length = second & 0x7F
            if length == 126:
                while len(buf) < 4:
                    buf += sock.recv(65536)
                length = struct.unpack("!H", buf[2:4])[0]
                index = 4
            elif length == 127:
                while len(buf) < 10:
                    buf += sock.recv(65536)
                length = struct.unpack("!Q", buf[2:10])[0]
                index = 10
            if second & 0x80:  # server frames are not masked, but be safe
                index += 4
            while len(buf) < index + length:
                chunk = sock.recv(65536)
                if not chunk:
                    return None
                buf += chunk
            payload = buf[index:index + length]
            buf = buf[index + length:]
            opcode = first & 0x0F
            if opcode == 0x8:
                return None
            if opcode in (0x9, 0xA):
                continue
            try:
                reply = json.loads(payload.decode("utf-8", "replace"))
            except Exception:
                continue
            if reply.get("id") == 1:
                return reply
        return None
    except Exception:
        return None
    finally:
        try:
            sock.close()
        except Exception:
            pass


def _count_cookies_cdp(port: int) -> int:
    """Live cookie count through CDP (the accurate one). ``-1`` = unreadable.

    This is the only reliable way while Chrome is running: the SQLite file's WAL
    is open, so a lock-free read can fail even when the store is perfectly fine.
    """
    ws_url = _ws_url(port)
    if not ws_url:
        return -1
    reply = _cdp_call(ws_url, "Storage.getCookies")
    if not reply:
        return -1
    cookies = reply.get("result", {}).get("cookies")
    return len(cookies) if isinstance(cookies, list) else -1


def _count_cookies(profile: Path) -> int:
    """Cookie rows from the on-disk store. ``-1`` means unreadable — never "zero"."""
    candidates = (
        profile / "Default" / "Network" / "Cookies",
        profile / "Network" / "Cookies",
        profile / "Default" / "Cookies",
        profile / "Cookies",
    )
    for db in candidates:
        if not db.exists():
            continue
        try:
            con = sqlite3.connect(f"file:{db.as_posix()}?mode=ro", uri=True, timeout=2)
            try:
                row = con.execute("SELECT COUNT(*) FROM cookies").fetchone()
                return int(row[0]) if row else -1
            finally:
                con.close()
        except Exception:
            continue
    return -1


def _looks_headless(version: Dict[str, Any] | None) -> bool:
    if not version:
        return False
    ua = str(version.get("User-Agent") or "")
    return "HeadlessChrome" in ua


def _pages(port: int) -> list[Dict[str, Any]]:
    targets = _get_json(port, "/json/list")
    if not isinstance(targets, list):
        return []
    return [t for t in targets if t.get("type") == "page"]


def handle_browser_health(
    profile_port: int = PROFILE_PORT,
    agent_port: int = AGENT_PORT,
    profile_dir: str = "",
) -> Dict[str, Any]:
    """Report the local browser stack (read-only)."""
    profile = Path(profile_dir) if profile_dir else _openamer_home() / "chrome-profile"

    version = _get_json(profile_port, "/json/version")
    alive = version is not None
    headless = _looks_headless(version)
    pages = _pages(profile_port) if alive else []
    if alive and not headless:
        cookie_count = _count_cookies_cdp(profile_port)
        cookie_source = "cdp"
        if cookie_count < 0:
            cookie_count = _count_cookies(profile)
            cookie_source = "sqlite" if cookie_count >= 0 else "unreadable"
    else:
        cookie_count = _count_cookies(profile)
        cookie_source = "sqlite" if cookie_count >= 0 else "unreadable"
    agent_version = _get_json(agent_port, "/json/version")

    reasons: list[str] = []
    if not alive:
        reasons.append(f"CDP browser on :{profile_port} is not answering")
    if headless:
        reasons.append(
            f":{profile_port} is served by a HEADLESS Chrome — the visible profile browser is gone"
        )
    if alive and cookie_count == 0:
        reasons.append("cookie store is empty — the profile has lost its logins")
    elif alive and 0 < cookie_count < MIN_HEALTHY_COOKIES:
        reasons.append(
            f"only {cookie_count} cookies (< {MIN_HEALTHY_COOKIES}) — the profile is effectively wiped"
        )
    elif alive and cookie_count < 0:
        reasons.append("cookie store is unreadable (no lock-free read possible)")
    if agent_version is None:
        reasons.append(f"agent browser on :{agent_port} is not running")

    if not alive:
        verdict = "down"
    elif reasons:
        verdict = "degraded"
    else:
        verdict = "ok"

    return {
        "verdict": verdict,
        "reasons": reasons,
        "profile": {
            "port": profile_port,
            "alive": alive,
            "headless": headless,
            "browser": (version or {}).get("Browser"),
            "user_agent": (version or {}).get("User-Agent"),
            "pages": len(pages),
            "has_x_tab": any("x.com" in str(p.get("url", "")) for p in pages),
            "cookies": cookie_count,
            "cookies_readable": cookie_count >= 0,
            "cookies_source": cookie_source,
            "profile_dir": str(profile),
            "profile_dir_exists": profile.exists(),
        },
        "agent": {
            "port": agent_port,
            "alive": agent_version is not None,
            "browser": (agent_version or {}).get("Browser"),
        },
        "thresholds": {"min_healthy_cookies": MIN_HEALTHY_COOKIES},
    }


BROWSER_HEALTH_SCHEMA: Dict[str, Any] = {
    "name": "browser_health",
    "description": (
        "Report the local CDP browser stack without changing it: is the visible "
        "profile browser on :9222 alive or replaced by a headless impostor, how "
        "many live cookies the profile holds, and whether the agent browser on "
        ":9223 is up. Returns a verdict (ok/degraded/down) plus the reasons."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "profile_port": {
                "type": "integer",
                "description": "CDP port of the visible profile browser (default 9222).",
            },
            "agent_port": {
                "type": "integer",
                "description": "CDP port of the agent browser (default 9223).",
            },
            "profile_dir": {
                "type": "string",
                "description": "Chrome profile directory to inspect (default <OPENAMER_HOME>/chrome-profile).",
            },
        },
    },
}


def register(ctx) -> None:
    ctx.register_tool(
        name="browser_health",
        toolset="browser_health",
        schema=BROWSER_HEALTH_SCHEMA,
        handler=handle_browser_health,
        description="Read-only health of the local CDP browser stack.",
        emoji="🌐",
    )
