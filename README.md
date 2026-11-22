# browser-health

An OpenAmer plugin that reports the state of the local CDP browser stack — read-only.

It answers the questions that actually break browser automation on a long-lived
install, in one call:

| Question | Why it matters |
|---|---|
| Is the CDP profile browser on `:9222` alive? | every browser tool silently fails without it |
| Is it the *visible* Chrome or a headless impostor that took the port? | a headless instance has the same profile path and no usable session |
| How many live cookies does the profile hold? | the store ages out (~30 days); a near-empty store means lost logins, not a healthy session |
| Is the agent browser on `:9223` up? | the two are different browsers and must not be confused |

Verdict is `ok` / `degraded` / `down`, with the reasons spelled out.

## Install

```
openamer plugins install openamer/openamer-plugin-browser-health
openamer plugins enable browser-health
openamer gateway restart      # the tool joins the toolset on the next start
```

Or, from the desktop app: **Fähigkeiten → Plugins → search "browser-health" → Install**.

## The tool

```jsonc
{
  "verdict": "ok",
  "reasons": [],
  "profile": {
    "port": 9222,
    "alive": true,
    "headless": false,
    "browser": "Chrome/157.0.8103.80",
    "pages": 1,
    "has_x_tab": false,
    "cookies": 444,
    "cookies_readable": true,
    "cookies_source": "cdp"
  },
  "agent": { "port": 9223, "alive": true },
  "thresholds": { "min_healthy_cookies": 50 }
}
```

Arguments: `profile_port` (default 9222), `agent_port` (default 9223),
`profile_dir` (default `$OPENAMER_HOME/chrome-profile`).

## Two design decisions

**Cookies are counted over CDP, not from the SQLite file.** While Chrome runs, the
file's WAL is open; a lock-free read can fail on a perfectly healthy profile. So
the count comes from `Storage.getCookies`.

**The CDP client is stdlib-only.** `websocket-client` is installed in some OpenAmer
runtimes and not others. A health tool that reports "unreadable" because a package
is missing is worse than useless, so the plugin speaks the minimum of RFC 6455 it
needs: handshake, one masked text frame, read frames until the matching `id`.

## What it never does

No navigation, no cookie **values**, no writes to the profile, no process kills.
It reports; the watchdog and the user act.

## License

MIT — see [LICENSE](LICENSE).
