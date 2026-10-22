"""
Hachage des mots de passe avec Argon2id (A02 / A07).

Argon2id est le gagnant de la Password Hashing Competition et l'algorithme
recommandé en premier choix par l'OWASP Password Storage Cheat Sheet.
Il est « memory-hard » : chaque essai coûte de la RAM, ce qui rend le
cassage massif sur GPU/ASIC beaucoup plus coûteux qu'avec SHA-256 ou MD5.

Le sel (16 octets aléatoires) et les paramètres sont inclus dans la chaîne
produite ($argon2id$v=19$m=...,t=...,p=...$sel$hash) : rien à stocker à part.
"""
from __future__ import annotations

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

# Paramètres alignés sur la recommandation OWASP « m=19 MiB, t=2, p=1 » minimum ;
# on monte ici à 64 MiB / t=3, raisonnable pour un serveur.
_hasher = PasswordHasher(
    time_cost=3,
    memory_cost=64 * 1024,  # en KiB -> 64 MiB
    parallelism=1,
    hash_len=32,
    salt_len=16,
)

# Hash factice calculé une fois : utilisé quand l'utilisateur n'existe pas,
# pour que la réponse prenne le même temps qu'avec un vrai compte.
# Sans cela, le temps de réponse révélerait quels identifiants existent
# (énumération de comptes par canal temporel).
_DUMMY_HASH = _hasher.hash("dummy-password-for-timing-equalization")


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(stored_hash: str | None, password: str) -> bool:
    """Vérifie un mot de passe en temps constant (comparaison faite par argon2)."""
    try:
        return _hasher.verify(stored_hash or _DUMMY_HASH, password) and stored_hash is not None
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def needs_rehash(stored_hash: str) -> bool:
    """Vrai si le hash a été fait avec des paramètres plus faibles qu'aujourd'hui.

    Permet d'augmenter le coût au fil du temps : le hash est mis à jour
    de manière transparente à la prochaine connexion réussie.
    """
    return _hasher.check_needs_rehash(stored_hash)
# GROGNON
