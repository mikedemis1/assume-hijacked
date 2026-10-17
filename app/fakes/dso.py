"""Fake of the grid operator (DSO), which carries out disconnection orders. See app/fakes/__init__.py."""

from app.fakes import FAKES, run

if __name__ == "__main__":
    run(FAKES["dso"])
