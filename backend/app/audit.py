"""
Journalisation des événements de sécurité (A09 - Security Logging and Monitoring Failures).

Les événements sont écrits en JSON sur stdout (récupérables par
`docker compose logs`, puis par un SIEM). On journalise QUI, QUOI, QUAND,
D'OÙ — mais jamais de mot de passe, de jeton de session ni de contenu de note.
Les valeurs fournies par l'utilisateur sont encodées par json.dumps, ce qui
neutralise l'injection de logs (CRLF, faux événements).
"""
from __future__ import annotations

import json
import logging
import sys
from datetime import datetime, timezone

from flask import g, has_request_context, request

_logger = logging.getLogger("security")


def setup_logging(level: int = logging.INFO) -> None:
    if _logger.handlers:
        return
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter("%(message)s"))
    _logger.addHandler(handler)
    _logger.setLevel(level)
    _logger.propagate = False


def security_event(event: str, outcome: str = "success", **fields) -> None:
    record = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "type": "security",
        "event": event,
        "outcome": outcome,
    }
    if has_request_context():
        record["ip"] = request.remote_addr
        record["path"] = request.path
        user = g.get("user")
        if user is not None:
            record["user_id"] = str(user.id)
    record.update({k: str(v) for k, v in fields.items()})
    _logger.info(json.dumps(record, ensure_ascii=True))
# GROGNON
