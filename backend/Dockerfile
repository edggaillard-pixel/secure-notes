# syntax=docker/dockerfile:1
# ---------------------------------------------------------------------------
# Image du backend. Durcissement :
# - image slim (surface d'attaque réduite), dépendances épinglées ;
# - exécution en utilisateur non-root (UID fixe) ;
# - pas de compilateur ni de cache pip dans l'image finale ;
# - le répertoire d'uploads est un volume hors de l'arborescence du code.
# ---------------------------------------------------------------------------
FROM python:3.13-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# libmagic : détection du type MIME réel des fichiers uploadés.
RUN apt-get update \
    && apt-get install -y --no-install-recommends libmagic1 \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system --gid 10001 app \
    && useradd --system --uid 10001 --gid app --no-create-home --shell /usr/sbin/nologin app

WORKDIR /srv
COPY requirements.txt .
RUN pip install -r requirements.txt

# ---- Image de tests : docker compose --profile test run --rm tests ----------
FROM base AS test
COPY requirements-dev.txt .
RUN pip install -r requirements-dev.txt
COPY . .
USER app
CMD ["python", "-m", "pytest"]

# ---- Image de production ---------------------------------------------------
FROM base AS runtime
COPY app ./app
COPY wsgi.py docker-entrypoint.sh ./
RUN chmod 0555 docker-entrypoint.sh \
    && mkdir -p /data/uploads \
    && chown app:app /data/uploads \
    && chmod 0700 /data/uploads

USER app
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=3s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/api/health').status==200 else 1)"
ENTRYPOINT ["./docker-entrypoint.sh"]
# GROGNON
