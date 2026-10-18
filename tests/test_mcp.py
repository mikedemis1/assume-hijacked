import json

from app.agent.gateway import ToolGateway
from app.tools import serve
from tests.conftest import open_lease
from tests.toolhttp import KEYS, AppToolGateway


def gateway(settings, *tools):
    return AppToolGateway(settings, *KEYS, tools=tools)


def test_lookup_account_over_mcp(settings, admin):
    out = gateway(settings, "lookup_account").call("lookup_account", {"lease": open_lease(admin, 1)})
    assert json.loads(out)["name"] == "Eleni Papadopoulou"


def test_tool_error_comes_back_as_text(settings):
    out = gateway(settings, "read_ticket").call("read_ticket", {"lease": "0" * 64})
    assert out.startswith("ERROR:")


def test_lease_error_comes_back_as_lease_invalid_without_database_detail(settings):
    out = gateway(settings, "read_ticket").call("read_ticket", {"lease": "0" * 64})
    assert "lease invalid" in out
    assert "PL/pgSQL" not in out and "CONTEXT" not in out


def test_each_tool_server_exists(settings):
    for tool in serve.TOOLS:
        assert serve.build_server(tool, settings) is not None


def test_unreachable_tool_comes_back_as_error_text():
    out = ToolGateway({"read_ticket": "http://127.0.0.1:9/mcp"}, KEYS[0]).call("read_ticket", {"lease": "0" * 64})
    assert out.startswith("ERROR:")
