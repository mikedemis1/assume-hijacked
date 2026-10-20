import pytest

from tests.conftest import reset_db

# Test files that never read the database. The other files in this folder get the fresh database
# of tests/conftest.py before every test; these skip the TRUNCATE, which only slows them down.
NO_DB = {"test_demo_timeline", "test_demo_sessions", "test_scripts", "test_pipeline", "test_risk_rules", "test_supply_chain", "test_ops", "test_llmgw"}


@pytest.fixture(autouse=True)
def fresh_db(request):
    """Replaces the autouse fixture of tests/conftest.py for the files in NO_DB only."""
    if request.module.__name__.rsplit(".", 1)[-1] in NO_DB:
        return
    reset_db(request.getfixturevalue("admin"))
