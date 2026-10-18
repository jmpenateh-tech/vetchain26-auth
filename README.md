# auth-service — VetChain

Servicio de identidad de VetChain. Gestiona el registro, la autenticación (JWT), los roles, el
ámbito administrativo, la foto de perfil y la auditoría de la plataforma.

## Responsabilidad en la arquitectura

Es la **fuente de verdad de usuarios y permisos**. Los demás microservicios no guardan usuarios:
validan el token y consultan a auth-service para resolver la identidad y el ámbito de un administrador.

- **Autenticación**: emite el JWT que el API Gateway y todos los servicios verifican.
- **Jerarquía de roles** (desde 2.10):
  - `master-admin` — administrador general, ve y gestiona todo el sistema.
  - `admin` — gerente limitado a **sus propios usuarios** (ámbito administrativo).
  - Roles operativos: `fabricante`, `distribuidor`, `veterinaria`.
- **Ámbito (`/scope`)**: determina qué usuarios puede ver/administrar cada gerente.
- **Auditoría**: registra accesos, cambios de cuenta y eventos firmados de todo el sistema.
- **Usuarios de demostración** y **acceso de demostración** (solo con `SEED_DEMO_USERS=true`).

## Tecnologías

| Componente | Versión |
|---|---|
| Node.js | `>=22.18.0 <23 \|\| >=23.6.0` |
| Express | ^5.2.1 |
| Prisma | `8.0.0-rc.15` (versión candidata fijada por sintaxis del esquema) |
| @prisma/orm-postgres | `8.0.0-rc.11` |
| bcrypt | ^6.0.0 |
| pg | 8.22.0 |
| dotenv | ^18.0.1 |

## Instalación y ejecución

**Método oficial (recomendado): Docker Compose**, desde la raíz del proyecto:

```bash
docker compose up -d --build --wait
```

**Ejecución directa** (requiere PostgreSQL accesible):

```bash
npm install
npm start            # ejecuta: node preflight.mjs && prisma db init && node index.js
```

`preflight.mjs` comprueba la conectividad con la base antes de arrancar y `prisma db init` crea la
tabla de usuarios de forma idempotente. El servicio escucha en `PORT` (3001 por defecto).

## Endpoints principales

| Método | Ruta | Acceso | Descripción |
|---|---|---|---|
| GET | `/` , `/health` | Público | Identificación y estado. |
| POST | `/login` | Público | Inicia sesión y devuelve el `token`. |
| POST | `/register` | Público | Registro (`fabricante`, `distribuidor`, `veterinaria`). La cuenta queda **pendiente de activación**. |
| GET | `/me` | Autenticado | Datos de la cuenta actual. |
| GET | `/session` | Autenticado | Comprueba la validez de la sesión y el rol. |
| POST | `/me/password` | Autenticado | Cambio de contraseña propia. |
| GET | `/me/admin` | Autenticado | Gerente responsable de la cuenta. |
| POST/DELETE | `/me/photo` | Autenticado | Alta/baja de la foto de perfil (data URL). |
| GET | `/users` , `/users/:id` | admin / master-admin | Listado y detalle (con ámbito). |
| POST | `/users` | admin / master-admin | Crea una cuenta. |
| PATCH | `/users/:id` | admin / master-admin | Actualiza/activa/desactiva una cuenta. |
| POST | `/users/:id/password` | admin / master-admin | Restablece la contraseña. |
| DELETE | `/users/:id/photo` | admin / master-admin | Retira la foto de una cuenta. |
| GET | `/entities` | Autenticado | Entidades de destino (fabricante/distribuidor/veterinaria). |
| GET | `/admins` | master-admin | Lista los gerentes. |
| PUT | `/users/:id/admin` | master-admin | Promueve/degradar un gerente. |
| POST | `/admins/:id/reassign-users` | master-admin | Reasigna los usuarios de un gerente. |
| GET | `/scope` | Autenticado | Ámbito de usuarios del gerente. |
| GET | `/audit` | admin / master-admin | Registro de auditoría (el master ve todo; el admin, su ámbito). |
| POST | `/internal/audit` | Interno | Eventos firmados del Gateway y los microservicios (no publicado en el Gateway). |

## Variables de entorno

| Variable | Defecto | Descripción |
|---|---|---|
| `PORT` | `3001` | Puerto de escucha. |
| `DATABASE_URL` | — | Cadena de conexión a PostgreSQL. |
| `JWT_SECRET` | — | Secreto para firmar/verificar los tokens. |
| `SEED_DEMO_USERS` | `false` | Si es `true`, crea las cuentas de demostración al arrancar. **En producción: `false`.** |
| `DEMO_ACCESS` | = `SEED_DEMO_USERS` | Activa el "acceso de demostración" que desbloquea la lista de Usuarios de prueba. |
| `DEMO_ACCESS_EMAIL` | `usuariosdeprueba@vetchain` | Correo del acceso de demostración. |
| `DEMO_ACCESS_PASSWORD` | `Usuarios_Prueba123` | Contraseña del acceso de demostración. |
| `MASTER_ADMIN_EMAIL` | — | Correo del administrador general a crear/promover en producción. |
| `MASTER_ADMIN_PASSWORD` | — | Contraseña del administrador general. |
| `MASTER_ADMIN_NAME` | — | Nombre del administrador general. |
| `PHOTO_MAX_KB` | `200` | Tamaño máximo de la foto de perfil. |
| `APP_TIMEZONE` | `America/Bogota` | Zona horaria del negocio. |

## Base de datos

Tablas administradas por Prisma (`User`) y por DDL propio en el esquema `auth_meta`:
`users` (identidad), `auth_meta` (estado activo + `user_admin` que define el ámbito administrativo) y
`auth_meta.profile_photo` (foto de perfil).

## Reglas de negocio

- `POST /register` **no** permite crear cuentas `admin` ni `master-admin`; tampoco permite duplicar
  correo ni nombre. La cuenta se crea **inactiva** hasta que un gerente la apruebe.
- **Aislamiento entre administradores**: un `admin` solo ve y gestiona sus propios usuarios; un
  `master-admin` ve todo. La migración no destructiva `migrateAdminScopes()` asigna usuarios huérfanos
  al gerente más antiguo.
- **Foto de perfil**: solo JPEG/PNG/WebP (no SVG), base64 válido, ≤ `PHOTO_MAX_KB` y la firma de los
  primeros bytes debe coincidir con el tipo declarado (rechaza archivos renombrados).
- **Acceso de demostración**: no es un usuario real (sin token ni rol); su correo está reservado y
  comparte el límite de intentos fallidos del login.

## Eventos

No publica ni consume en RabbitMQ. Expone `/internal/audit` para que los demás servicios envíen
eventos de auditoría firmados con el JWT.
