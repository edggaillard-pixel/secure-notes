"""
Chiffrement des données au repos (A02 - Cryptographic Failures).

Algorithme : AES-256-GCM (chiffrement authentifié, AEAD).
- Confidentialité : un dump de la base ou du volume d'uploads est illisible.
- Intégrité : toute modification d'un octet du chiffré fait échouer le
  déchiffrement (le « tag » GCM de 16 octets ne correspond plus).

Données associées (AAD) : on lie chaque chiffré à son contexte, par exemple
"note:<uuid>:content". Un attaquant ayant un accès en écriture à la base ne
peut donc pas copier le contenu chiffré de la note A dans la note B : le
déchiffrement échouerait car l'AAD ne correspond plus.

Format d'un blob :  version(1) | kid(1) | nonce(12) | chiffré + tag(16)
Le « kid » (key id) permet la rotation des clés : on chiffre toujours avec la
clé active et on garde les anciennes uniquement pour déchiffrer.

Nonce : 96 bits aléatoires par message (os.urandom). Avec une clé donnée, on
reste très loin de la limite de 2^32 messages recommandée par le NIST.
"""
from __future__ import annotations

import base64
import binascii
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

_VERSION = 1
_NONCE_LEN = 12
_HEADER_LEN = 2 + _NONCE_LEN


class DecryptionError(Exception):
    """Chiffré altéré, clé inconnue ou mauvais contexte (AAD)."""


class KeyRing:
    def __init__(self, spec: str):
        """spec = "1:base64key,2:base64key" — la première clé est la clé active."""
        self._keys: dict[int, AESGCM] = {}
        self.active_kid: int | None = None
        for part in spec.split(","):
            part = part.strip()
            if not part:
                continue
            kid_str, _, b64 = part.partition(":")
            try:
                kid = int(kid_str)
                key = base64.b64decode(b64, validate=True)
            except (ValueError, binascii.Error) as exc:
                raise ValueError("Format de DATA_ENCRYPTION_KEYS invalide") from exc
            if not 0 < kid < 256:
                raise ValueError("Le kid doit être compris entre 1 et 255")
            if len(key) != 32:
                raise ValueError("Chaque clé doit faire exactement 32 octets (AES-256)")
            if kid in self._keys:
                raise ValueError(f"kid dupliqué : {kid}")
            self._keys[kid] = AESGCM(key)
            if self.active_kid is None:
                self.active_kid = kid
        if self.active_kid is None:
            raise ValueError("Aucune clé de chiffrement fournie")

    def encrypt(self, plaintext: bytes, context: str) -> bytes:
        nonce = os.urandom(_NONCE_LEN)
        aead = self._keys[self.active_kid]
        ct = aead.encrypt(nonce, plaintext, context.encode())
        return bytes([_VERSION, self.active_kid]) + nonce + ct

    def decrypt(self, blob: bytes, context: str) -> bytes:
        if len(blob) < _HEADER_LEN + 16 or blob[0] != _VERSION:
            raise DecryptionError("Format de chiffré inconnu")
        aead = self._keys.get(blob[1])
        if aead is None:
            raise DecryptionError("Clé inconnue (kid)")
        nonce, ct = blob[2:_HEADER_LEN], blob[_HEADER_LEN:]
        try:
            return aead.decrypt(nonce, ct, context.encode())
        except InvalidTag as exc:
            raise DecryptionError("Authentification du chiffré échouée") from exc

    # Raccourcis pour du texte
    def encrypt_str(self, text: str, context: str) -> bytes:
        return self.encrypt(text.encode("utf-8"), context)

    def decrypt_str(self, blob: bytes, context: str) -> str:
        return self.decrypt(blob, context).decode("utf-8")

    def needs_reencrypt(self, blob: bytes) -> bool:
        """Vrai si le blob a été chiffré avec une ancienne clé (rotation)."""
        return len(blob) > 1 and blob[1] != self.active_kid


def keyring() -> KeyRing:
    """Trousseau de l'application courante (créé une fois dans create_app)."""
    from flask import current_app

    return current_app.extensions["keyring"]


def generate_key_spec(kid: int = 1) -> str:
    """Utilitaire : génère une clé AES-256 aléatoire au format attendu."""
    return f"{kid}:{base64.b64encode(os.urandom(32)).decode()}"
# GROGNON
