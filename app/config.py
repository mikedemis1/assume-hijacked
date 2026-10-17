"""Settings from environment variables. Defaults are for local development."""

from __future__ import annotations

import os
from dataclasses import dataclass

from app.common.calls import caller_auth_mode


def _bool(name: str) -> bool:
    return os.environ.get(name, "false").strip().lower() in {"1", "true", "yes"}


@dataclass(frozen=True)
class Settings:
    db_host: str
    db_port: int
    db_name: str
    vulnerable: bool
    credit_auto_max_eur: float
    credit_month_max_eur: float
    credit_day_global_max_eur: float
    moveout_max_per_hour: int
    occupier_wait_hours: int
    register_max_age_hours: int
    # The outside systems (fakes in this project, app/fakes). Empty: no call is made.
    dso_url: str
    sms_url: str
    register_url: str
    caller_auth: str  # compose or k8s: how a call says who is calling (app/common/calls.py)


def load() -> Settings:
    return Settings(
        db_host=os.environ.get("DB_HOST", "localhost"),
        db_port=int(os.environ.get("DB_PORT", "5432")),
        db_name=os.environ.get("DB_NAME", "supplier"),
        vulnerable=_bool("VULNERABLE"),
        credit_auto_max_eur=float(os.environ.get("CREDIT_AUTO_MAX_EUR", "50")),
        credit_month_max_eur=float(os.environ.get("CREDIT_MONTH_MAX_EUR", "100")),
        credit_day_global_max_eur=float(os.environ.get("CREDIT_DAY_GLOBAL_MAX_EUR", "1000")),
        moveout_max_per_hour=int(os.environ.get("MOVEOUT_MAX_PER_HOUR", "20")),
        occupier_wait_hours=int(os.environ.get("OCCUPIER_WAIT_HOURS", "72")),
        register_max_age_hours=int(os.environ.get("REGISTER_MAX_AGE_HOURS", "24")),
        dso_url=os.environ.get("DSO_URL", ""),
        sms_url=os.environ.get("SMS_URL", ""),
        register_url=os.environ.get("REGISTER_URL", ""),
        caller_auth=caller_auth_mode(),
    )
