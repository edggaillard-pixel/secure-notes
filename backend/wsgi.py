"""Point d'entrée WSGI (gunicorn wsgi:app) et CLI (flask --app wsgi ...)."""
from app import create_app

app = create_app()
# GROGNON
