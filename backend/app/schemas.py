"""
Validation stricte des entrées avec Pydantic (A03 / A04 / A08).

- Liste blanche : on décrit ce qui est accepté, tout le reste est refusé.
- extra="forbid" : un champ inattendu (ex. "owner_id" ou "is_admin") fait
  échouer la requête -> protection contre le « mass assignment ».
- Types stricts (StrictStr) : pas de conversion implicite 123 -> "123".
- Bornes de longueur partout : limite les abus de stockage et le DoS.
"""
from __future__ import annotations

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, ValidationError, model_validator

from .errors import ApiError

Username = Annotated[
    str,
    StringConstraints(strict=True, min_length=3, max_length=32, pattern=r"^[A-Za-z0-9_.-]+$"),
]
# Limite haute à 128 : Argon2 accepte plus, mais on évite qu'un mot de passe
# de plusieurs Mo ne serve à saturer le CPU.
Password = Annotated[str, StringConstraints(strict=True, min_length=12, max_length=128)]
LoginPassword = Annotated[str, StringConstraints(strict=True, min_length=1, max_length=128)]

# Petite liste illustrative ; en production, vérifier contre une liste de
# mots de passe compromis (ex. API k-anonymity de Have I Been Pwned).
_COMMON_PASSWORDS = frozenset({
    "password1234", "motdepasse123", "azertyuiop123", "123456789012",
    "qwertyuiop12", "administrator", "changeme1234", "iloveyou1234",
})


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class RegisterIn(_Strict):
    username: Username
    password: Password

    @model_validator(mode="after")
    def _password_policy(self):
        # NIST SP 800-63B : longueur minimale + liste noire, pas de règles
        # de composition arbitraires (« 1 majuscule, 1 symbole... »).
        low = self.password.lower()
        if low in _COMMON_PASSWORDS:
            raise ValueError("Mot de passe trop courant.")
        if self.username.lower() in low:
            raise ValueError("Le mot de passe ne doit pas contenir l'identifiant.")
        return self


class LoginIn(_Strict):
    username: Annotated[str, StringConstraints(strict=True, min_length=1, max_length=32)]
    password: LoginPassword


class ChangePasswordIn(_Strict):
    current_password: LoginPassword
    new_password: Password


class NoteIn(_Strict):
    title: Annotated[str, StringConstraints(strict=True, min_length=1, max_length=200)]
    content: Annotated[str, StringConstraints(strict=True, max_length=100_000)] = ""


class ShareIn(_Strict):
    username: Username
    permission: Literal["read", "write"]


def parse(model: type[_Strict], data: dict) -> _Strict:
    try:
        return model.model_validate(data)
    except ValidationError as exc:
        # On renvoie l'emplacement et le message, mais jamais la valeur reçue
        # (elle pourrait contenir un mot de passe).
        details = [
            {"field": ".".join(str(p) for p in e["loc"]) or None, "message": e["msg"]}
            for e in exc.errors(include_input=False, include_url=False)
        ]
        raise ApiError(400, "validation_error", "Données invalides.", details) from None
# GROGNON
