"""
Modèle de données.

Choix de sécurité :
- Identifiants UUIDv4 aléatoires : non devinables, contrairement à des entiers
  séquentiels (réduit l'énumération ; le vrai rempart contre l'IDOR reste
  le contrôle d'accès côté serveur, cf. security/access.py).
- Les contenus sensibles (titres, contenus de notes, noms de fichiers) sont
  stockés chiffrés (colonnes *_enc, type LargeBinary).
- La table des sessions ne stocke qu'une empreinte SHA-256 du jeton : une
  fuite de la base ne permet pas de détourner des sessions actives.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    String,
    UniqueConstraint,
    Uuid,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .extensions import db


def utcnow() -> datetime:
    """Horodatage UTC « naïf » : stocké tel quel, comparé toujours en UTC."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


class User(db.Model):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    # Stocké en minuscules : évite deux comptes « Alice » / « alice ».
    username: Mapped[str] = mapped_column(String(32), unique=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, nullable=False)

    sessions = relationship("Session", back_populates="user", cascade="all, delete-orphan")


class Session(db.Model):
    """Session côté serveur : révocable instantanément (logout, changement de mdp)."""

    __tablename__ = "sessions"

    token_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    csrf_token: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)

    user = relationship("User", back_populates="sessions")


class Note(db.Model):
    __tablename__ = "notes"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    owner_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    title_enc: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    content_enc: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, nullable=False)

    owner = relationship("User")


class StoredFile(db.Model):
    __tablename__ = "files"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    owner_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    # Nom sur disque : 32 caractères hexadécimaux aléatoires, sans extension.
    # Le nom d'origine n'est jamais utilisé pour construire un chemin.
    storage_name: Mapped[str] = mapped_column(String(32), unique=True, nullable=False)
    original_name_enc: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    mime_type: Mapped[str] = mapped_column(String(100), nullable=False)
    size_bytes: Mapped[int] = mapped_column(Integer, nullable=False)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, nullable=False)

    owner = relationship("User")


class Share(db.Model):
    """Partage nominatif d'une ressource (note ou fichier) avec un autre compte."""

    __tablename__ = "shares"
    __table_args__ = (
        UniqueConstraint("resource_type", "resource_id", "grantee_id", name="uq_share_target"),
        CheckConstraint("resource_type IN ('note', 'file')", name="ck_share_type"),
        CheckConstraint("permission IN ('read', 'write')", name="ck_share_perm"),
        Index("ix_share_grantee", "grantee_id", "resource_type"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    resource_type: Mapped[str] = mapped_column(String(8), nullable=False)
    resource_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False, index=True)
    owner_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    grantee_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    permission: Mapped[str] = mapped_column(String(8), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, nullable=False)

    grantee = relationship("User", foreign_keys=[grantee_id])
# GROGNON
