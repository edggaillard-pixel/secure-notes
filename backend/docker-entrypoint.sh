#!/bin/sh
set -eu

# Création des tables (idempotent). En production réelle : migrations Alembic.
flask --app wsgi init-db

# Gunicorn : serveur WSGI de production (jamais `flask run` en prod).
# --limit-request-* : bornes sur la ligne et les en-têtes (anti-DoS / smuggling).
exec gunicorn wsgi:app \
    --bind 0.0.0.0:8000 \
    --workers "${GUNICORN_WORKERS:-3}" \
    --timeout 30 \
    --graceful-timeout 20 \
    --limit-request-line 4094 \
    --limit-request-fields 50 \
    --limit-request-field_size 8190 \
    --access-logfile - \
    --error-logfile -
# GROGNON
