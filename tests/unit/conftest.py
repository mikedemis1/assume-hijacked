import pytest


@pytest.fixture(autouse=True)
def fresh_db():
    """Replaces the autouse fixture of tests/conftest.py, which truncates the test database.
    These tests never touch it."""
