"""Contract tests for the browser-health plugin.

Run: ``python -m pytest -q`` (pytest only; the plugin itself has no dependencies).

Everything the plugin claims is either a pure function or a deterministic
outcome of "nothing is listening", so most of this needs no browser. The one
live assertion is skipped when no CDP browser is running — a health tool must
never turn "nothing to check" into a red suite.
"""

from __future__ import annotations

import importlib.util
import inspect
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="module")
def plugin():
    spec = importlib.util.spec_from_file_location("browser_health_plugin", ROOT / "__init__.py")
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def test_manifest_declares_the_plugin_identity():
    manifest = yaml.safe_load((ROOT / "plugin.yaml").read_text(encoding="utf-8"))

    assert manifest["name"] == "browser-health"
    assert manifest["version"]
    for key in ("description", "author"):
        assert manifest.get(key), f"plugin.yaml is missing {key}"


def test_register_calls_only_the_real_context_api(plugin):
    """`register(ctx)` must satisfy PluginContext.register_tool's actual kwargs."""
    from openamer_cli.plugins import PluginContext

    accepted = set(inspect.signature(PluginContext.register_tool).parameters) - {"self"}
    calls: list[dict] = []

    class Ctx:
        def register_tool(self, **kwargs):
            assert not set(kwargs) - accepted, f"unknown kwargs: {set(kwargs) - accepted}"
            calls.append(kwargs)

    plugin.register(Ctx())

    assert len(calls) == 1
    tool = calls[0]
    assert tool["name"] == "browser_health"
    assert tool["toolset"] == "browser_health"
    assert callable(tool["handler"])
    assert tool["schema"]["parameters"]["type"] == "object"


@pytest.mark.parametrize(
    ("user_agent", "expected"),
    [
        ("Mozilla/5.0 HeadlessChrome/157.0.0.0", True),
        ("Mozilla/5.0 (Windows NT 10.0) Chrome/157.0.0.0", False),
        ("", False),
        (None, False),
    ],
)
def test_headless_detection_reads_the_user_agent(plugin, user_agent, expected):
    version = {"User-Agent": user_agent} if user_agent is not None else None

    assert plugin._looks_headless(version) is expected


def test_unreachable_ports_report_down_with_a_reason(plugin):
    """Deterministic: nothing listens on :9, so this exercises the failure path."""
    result = plugin.handle_browser_health(profile_port=9, agent_port=9)

    assert result["verdict"] == "down"
    assert result["reasons"], "a down verdict must carry its reason"
    assert result["profile"]["alive"] is False
    assert result["agent"]["alive"] is False


def test_cookie_count_is_never_silently_zero(plugin, tmp_path):
    """No cookie store on disk means "unreadable" (-1), not "zero cookies"."""
    assert plugin._count_cookies(tmp_path) == -1


def test_live_stack_reports_a_readable_cookie_count(plugin):
    probe = plugin.handle_browser_health()
    if not probe["profile"]["alive"]:
        pytest.skip("no CDP browser on :9222 in this environment")

    profile = probe["profile"]
    assert profile["headless"] is False, "the profile port is served by a headless Chrome"
    assert profile["cookies"] >= 0, "cookie count must be readable on a live profile"
    assert profile["cookies_source"] == "cdp"
    assert probe["verdict"] in ("ok", "degraded")
