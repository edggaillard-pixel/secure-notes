#!/bin/sh
# Génère un certificat auto-signé au premier démarrage (environnement local).
# La clé privée est créée DANS le conteneur et conservée dans un volume :
# elle n'est jamais embarquée dans l'image ni dans le dépôt Git.
# En production : remplacer par un certificat Let's Encrypt (certbot / Caddy).
set -eu
CERT_DIR=/etc/nginx/certs
if [ ! -s "$CERT_DIR/server.key" ]; then
    echo "Génération d'un certificat TLS auto-signé (localhost)..."
    openssl req -x509 -nodes -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
        -days 365 -subj "/CN=localhost" \
        -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" \
        -keyout "$CERT_DIR/server.key" -out "$CERT_DIR/server.crt"
    chmod 600 "$CERT_DIR/server.key"
fi
# GROGNON
