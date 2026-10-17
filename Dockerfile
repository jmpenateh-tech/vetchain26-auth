# syntax=docker/dockerfile:1
#
# Node 22 (no 20): auth-service importa "./prisma/db.ts" directamente y su
# package.json exige Node >=22.18.0 <23 || >=23.6.0 (type stripping nativo).
#
# node:22-slim (Debian/glibc) en lugar de node:22-alpine (musl) — motivo técnico:
# Prisma 8 RC instala como dependencias de producción ~630 paquetes, entre ellos
# "workerd" (runtime de Cloudflare). En el lockfile, workerd solo publica binarios
# para glibc (no existe variante musl/Alpine) y ejecuta un script de instalación.
# En Alpine eso puede hacer fallar "npm ci". Con glibc ese riesgo desaparece y el
# resto de binarios (bcrypt, esbuild, sharp...) tienen variante glibc en el lockfile.
# Los otros 9 servicios no tienen estas dependencias y siguen en node:22-alpine.
FROM node:22-slim

WORKDIR /app

# 3.1: modo no interactivo. Render construye y arranca sin terminal (sin TTY); con
# CI=true el CLI de Prisma no se queda esperando respuestas a preguntas interactivas.
ENV CI=true

# Instala solo dependencias de producción usando el lockfile (build reproducible)
COPY package*.json ./
RUN npm ci --omit=dev

# Copia el resto del código del servicio (.dockerignore excluye node_modules y .env)
COPY . .

# Regenera el contrato de Prisma 8 a partir de prisma/schema.prisma (no necesita
# base de datos). El CLI lo escribe como prisma/schema.json + schema.d.ts, pero el
# runtime (prisma/db.ts) importa prisma/contract.json + contract.d.ts. Se copian
# para que la app use SIEMPRE el contrato recién generado y no uno desactualizado.
# Si el CLI no generara esos archivos, el build falla aquí con un mensaje claro.
#
# 3.1: prisma.config.ts lee process.env.DATABASE_URL al cargarse. Durante el build
# de Docker esa variable NO existe (Render solo la entrega a los comandos del build
# si el Dockerfile la declara como ARG, y aquí no hace falta porque "contract emit"
# no se conecta a la base). Para que la validación de la configuración no dependa
# de eso, este RUN usa un valor de relleno SOLO durante este comando: no queda en
# la imagen ni en sus variables, y en ejecución se usa la DATABASE_URL real.
RUN set -e; \
    DATABASE_URL="postgresql://build:build@localhost:5432/build" npx prisma contract emit; \
    if [ ! -f prisma/schema.json ] || [ ! -f prisma/schema.d.ts ]; then \
      echo "ERROR: 'prisma contract emit' no genero prisma/schema.json / schema.d.ts" >&2; exit 1; \
    fi; \
    cp prisma/schema.json prisma/contract.json; \
    cp prisma/schema.d.ts prisma/contract.d.ts

EXPOSE 3001

# npm start = "node preflight.mjs && prisma db init && node index.js"
#   preflight.mjs (3.1): revisa DATABASE_URL y explica en los logs qué está mal.
#   prisma db init: crea la tabla si falta (idempotente).
CMD ["npm", "start"]
