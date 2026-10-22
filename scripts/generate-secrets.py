#!/usr/bin/env python3
"""
Génère un fichier .env avec des secrets aléatoires (CSPRNG du système).

Usage :  python3 scripts/generate-secrets.py > .env
Aucune dépendance externe. Ne jamais committer le .env produit.
"""
import base64
import os
import secrets

db_password = secrets.token_urlsafe(24)
redis_password = secrets.token_urlsafe(24)
encryption_key = base64.b64encode(os.urandom(32)).decode()

print(f"""# Généré par scripts/generate-secrets.py — NE PAS COMMITTER
POSTGRES_DB=securenotes
POSTGRES_USER=securenotes
POSTGRES_PASSWORD={db_password}
REDIS_PASSWORD={redis_password}

# Clé AES-256-GCM (kid 1). Pour une rotation : ajouter la nouvelle clé EN TÊTE
# ("2:nouvelle,1:ancienne"), redémarrer, puis rechiffrer les données.
DATA_ENCRYPTION_KEYS=1:{encryption_key}

# Origine publique de l'application (doit correspondre à l'URL du navigateur)
ALLOWED_ORIGINS=https://localhost:8443
HTTPS_PORT=8443
HTTP_PORT=8080""")
# GROGNON
