# syntax=docker/dockerfile:1
# ---- 1. Build de la SPA ------------------------------------------------------
FROM node:22-alpine AS build
WORKDIR /app
COPY package.json package-lock.json ./
# npm ci : installe exactement les versions du lockfile (build reproductible).
RUN npm ci --no-audit --no-fund
COPY index.html vite.config.js ./
COPY src ./src
RUN npm run build

# ---- 2. Nginx non-root -------------------------------------------------------
# Image « unprivileged » : Nginx tourne en UID 101 et écoute sur 8080/8443.
FROM nginxinc/nginx-unprivileged:1.27-alpine
USER root
RUN apk add --no-cache openssl \
    && mkdir -p /etc/nginx/certs /etc/nginx/snippets /etc/nginx/templates \
    && chown 101:101 /etc/nginx/certs \
    && rm -f /etc/nginx/conf.d/default.conf
# Le dossier templates est traité par envsubst au démarrage (${HTTPS_PORT}).
COPY nginx/default.conf /etc/nginx/templates/default.conf.template
COPY nginx/security-headers.conf /etc/nginx/snippets/security-headers.conf
COPY --chmod=0555 nginx/10-generate-cert.sh /docker-entrypoint.d/10-generate-cert.sh
COPY --from=build /app/dist /usr/share/nginx/html
USER 101
EXPOSE 8080 8443
# GROGNON
