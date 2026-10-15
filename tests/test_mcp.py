import json

from app.agent.gateway import ToolGateway
from app.tools import serve


def gateway(settings, *tools):
    return ToolGateway({t: serve.build_server(t, settings) for t in tools})


def test_lookup_account_over_mcp(settings):
    out = gateway(settings, "lookup_account").call("lookup_account", {"ticket_id": 1})
    assert json.loads(out)["name"] == "Eleni Papadopoulou"


def test_tool_error_comes_back_as_text(settings):
    out = gateway(settings, "read_ticket").call("read_ticket", {"ticket_id": 999})
    assert out.startswith("ERROR:")


def test_each_tool_server_exists(settings):
    for tool in serve.TOOLS:
        assert serve.build_server(tool, settings) is not None


def test_unreachable_tool_comes_back_as_error_text():
    out = ToolGateway({"read_ticket": "http://127.0.0.1:9/mcp"}).call("read_ticket", {"ticket_id": 1})
    assert out.startswith("ERROR:")
