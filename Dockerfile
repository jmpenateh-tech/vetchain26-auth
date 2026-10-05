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
RUN set -e; \
    npx prisma contract emit; \
    if [ ! -f prisma/schema.json ] || [ ! -f prisma/schema.d.ts ]; then \
      echo "ERROR: 'prisma contract emit' no genero prisma/schema.json / schema.d.ts" >&2; exit 1; \
    fi; \
    cp prisma/schema.json prisma/contract.json; \
    cp prisma/schema.d.ts prisma/contract.d.ts

EXPOSE 3001

# npm start = "prisma db init && node index.js" (crea la tabla si falta; idempotente)
CMD ["npm", "start"]
