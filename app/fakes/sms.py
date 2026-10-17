"""Fake of the SMS provider, which tells occupiers about a move-out. See app/fakes/__init__.py."""

from app.fakes import FAKES, run

if __name__ == "__main__":
    run(FAKES["sms"])
