"""Settings from environment variables. Defaults are for local development."""

from __future__ import annotations

import os
from dataclasses import dataclass

from app.common.calls import caller_auth_mode


@dataclass(frozen=True)
class Settings:
    db_host: str
    db_port: int
    db_name: str
    credit_auto_max_eur: float
    credit_month_max_eur: float
    credit_day_global_max_eur: float
    caller_auth: str  # k8s, the only mode: how a call says who is calling (app/common/calls.py)


def load() -> Settings:
    return Settings(
        db_host=os.environ.get("DB_HOST", "localhost"),
        db_port=int(os.environ.get("DB_PORT", "5432")),
        db_name=os.environ.get("DB_NAME", "supplier"),
        credit_auto_max_eur=float(os.environ.get("CREDIT_AUTO_MAX_EUR", "50")),
        credit_month_max_eur=float(os.environ.get("CREDIT_MONTH_MAX_EUR", "100")),
        credit_day_global_max_eur=float(os.environ.get("CREDIT_DAY_GLOBAL_MAX_EUR", "1000")),
        caller_auth=caller_auth_mode(),
    )
