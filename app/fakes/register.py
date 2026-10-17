"""Fake of the state register of homes with life-support equipment. See app/fakes/__init__.py."""

from app.fakes import FAKES, run

if __name__ == "__main__":
    run(FAKES["register"])
