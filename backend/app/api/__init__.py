"""Blueprints de l'API REST (/api/...)."""
from datetime import datetime


def iso(dt: datetime) -> str:
    """Horodatage UTC au format ISO 8601 avec suffixe Z."""
    return dt.replace(microsecond=0).isoformat() + "Z"
# GROGNON
