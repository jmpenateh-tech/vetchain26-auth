import express from "express";
import bcrypt from "bcrypt";
import pg from "pg";
import { db } from "./prisma/db.ts";
import { resolveSecret, signToken, verifyToken, bearer } from "./jwt.js";

// =============================================================================
// Auth Service — VetChain 2.4
//
// Antes (2.3) el panel del administrador creaba las cuentas SOLO en el navegador
// (localStorage) y el login consultaba este servicio: las cuentas nuevas nunca
// existían aquí y el login respondía "Credenciales inválidas". Ahora:
//   - POST /users (solo admin, con token) crea la cuenta real (bcrypt) con su rol.
//   - POST /login devuelve un token JWT que el gateway usa para autorizar por rol.
//   - Las cuentas se pueden desactivar/reactivar y su contraseña se puede restablecer.
//
// Persistencia: la tabla de usuarios la sigue creando y definiendo Prisma 8
// (prisma/schema.prisma, "prisma db init"). Las consultas que la API de Prisma
// usada en el proyecto no cubre (listar, actualizar) se hacen con "pg" sobre esa
// misma tabla, sin cambiar su estructura. El estado activo/inactivo vive en una
// tabla aparte (esquema auth_meta) para no alterar el contrato de Prisma.
// =============================================================================

const app = express();
const PORT = process.env.PORT || 3001;
const JWT_SECRET = resolveSecret("auth-service");
const TOKEN_TTL = Number(process.env.TOKEN_TTL_SECONDS) || 8 * 3600;

export const ROLES = ["admin", "fabricante", "distribuidor", "veterinaria"];
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const MIN_PASSWORD = 6;
const SEED_DEMO_USERS = String(process.env.SEED_DEMO_USERS || "").trim().toLowerCase() === "true";
// Registro público: desactivado. Las cuentas las crea el administrador.
const ALLOW_SELF_REGISTER = String(process.env.ALLOW_SELF_REGISTER || "").trim().toLowerCase() === "true";

const pool = new pg.Pool({ connectionString: process.env.DATABASE_URL, max: Number(process.env.DB_POOL_MAX) || 5 });
pool.on("error", (e) => console.error("[db] error en una conexión inactiva:", e.message));
const USER_TABLE = 'public."user"';

app.use(express.json());
app.use((req, _res, next) => {
  if (req.body === undefined) req.body = {};
  next();
});

const err = (res, status, message, extra = {}) => res.status(status).json({ error: message, ...extra });

const publicUser = (u, active = true) => ({
  id: u.id,
  email: u.email,
  username: u.username,
  name: u.name,
  role: u.role,
  active,
  createdAt: u.createdAt ?? null,
});

// -----------------------------------------------------------------------------
// Estado de la cuenta (activa / desactivada)
// -----------------------------------------------------------------------------
async function initMeta() {
  await pool.query(`
    CREATE SCHEMA IF NOT EXISTS auth_meta;
    CREATE TABLE IF NOT EXISTS auth_meta.account_status(
      user_id INT PRIMARY KEY,
      active BOOLEAN NOT NULL DEFAULT true,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now());`);
}

async function isActive(userId) {
  const r = await pool.query("select active from auth_meta.account_status where user_id=$1", [userId]);
  return r.rowCount ? r.rows[0].active : true; // sin fila = activa
}

async function setActive(userId, active) {
  await pool.query(
    `insert into auth_meta.account_status(user_id,active) values($1,$2)
     on conflict(user_id) do update set active=excluded.active, updated_at=now()`,
    [userId, active]);
}

async function findById(id) {
  const r = await pool.query(
    `select u.id,u.email,u.username,u.name,u.role,u.password,u."createdAt",
            coalesce(s.active,true) as active
       from ${USER_TABLE} u left join auth_meta.account_status s on s.user_id=u.id
      where u.id=$1`, [id]);
  return r.rows[0] || null;
}

// -----------------------------------------------------------------------------
// Validaciones compartidas
// -----------------------------------------------------------------------------
function validateNewUser({ name, email, password, role }) {
  if (!name || !String(name).trim()) return "El nombre es obligatorio";
  if (!email) return "El correo es obligatorio";
  if (!EMAIL_RE.test(email)) return "El correo no tiene un formato válido";
  if (typeof password !== "string" || password.length < MIN_PASSWORD) {
    return `La contraseña debe tener al menos ${MIN_PASSWORD} caracteres`;
  }
  if (!ROLES.includes(role)) return `Rol no válido. Roles: ${ROLES.join(", ")}`;
  return null;
}

// Nombre de usuario único derivado del correo (ana.perez@x.com -> ana.perez, ana.perez2, ...)
async function uniqueUsername(email) {
  const base = email.split("@")[0].replace(/[^a-z0-9._-]/gi, "").toLowerCase() || "usuario";
  for (let i = 1; i < 1000; i++) {
    const candidate = i === 1 ? base : `${base}${i}`;
    const taken = await db.orm.public.User.where({ username: candidate }).first();
    if (!taken) return candidate;
  }
  return `${base}${Date.now()}`;
}

async function createUser({ name, email, password, role }) {
  const user = await db.orm.public.User.create({
    email,
    username: await uniqueUsername(email),
    password: await bcrypt.hash(password, 10),
    name: String(name).trim(),
    role,
  });
  await setActive(user.id, true);
  return user;
}

// -----------------------------------------------------------------------------
// Middleware de autenticación (el gateway ya valida, esto es defensa en profundidad)
// -----------------------------------------------------------------------------
function requireAuth(req, res, next) {
  const payload = verifyToken(bearer(req), JWT_SECRET);
  if (!payload) return err(res, 401, "Sesión no válida o expirada. Inicia sesión de nuevo.");
  req.auth = payload;
  next();
}
function requireAdmin(req, res, next) {
  requireAuth(req, res, () => {
    if (req.auth.role !== "admin") return err(res, 403, "Solo un administrador puede gestionar usuarios");
    next();
  });
}

// ==========================================
// HEALTH CHECK
// ==========================================
app.get("/", (req, res) => {
  res.json({ service: "auth-service", status: "ok", message: "Auth service funcionando correctamente" });
});

app.get("/health", async (req, res) => {
  try {
    await db.orm.public.User.where({ email: "health-check@invalid" }).first();
    res.json({ status: "ok", database: "ok" });
  } catch (error) {
    console.error("Error en /health:", error.message);
    res.status(503).json({ status: "down" });
  }
});

// ==========================================
// LOGIN
// ==========================================
// Acepta un identificador (correo o nombre de usuario). Por compatibilidad también
// acepta los campos "email" y "username" que enviaba el frontend 2.3.
async function findUserForLogin({ identifier, email, username }) {
  const candidates = [identifier, email, username].filter((v) => typeof v === "string" && v.trim());
  for (const raw of candidates) {
    const value = raw.trim();
    if (value.includes("@")) {
      const u = await db.orm.public.User.where({ email: value.toLowerCase() }).first();
      if (u) return u;
    } else {
      const u = await db.orm.public.User.where({ username: value }).first()
        || await db.orm.public.User.where({ username: value.toLowerCase() }).first();
      if (u) return u;
    }
  }
  return null;
}

app.post("/login", async (req, res) => {
  try {
    const { identifier, email, username, password } = req.body;
    if ((!identifier && !email && !username) || !password) {
      return err(res, 400, "Escribe tu correo y tu contraseña");
    }
    const user = await findUserForLogin({ identifier, email, username });
    // Mismo mensaje si no existe o si la contraseña no coincide (no revela qué cuentas existen).
    if (!user || !(await bcrypt.compare(String(password), user.password))) {
      return err(res, 401, "Correo o contraseña incorrectos");
    }
    if (!(await isActive(user.id))) {
      return err(res, 403, "Tu cuenta está desactivada. Contacta al administrador.", { code: "account_disabled" });
    }
    if (!ROLES.includes(user.role)) {
      return err(res, 403, "Tu cuenta no tiene un rol asignado. Pide al administrador que te asigne uno.", { code: "no_role" });
    }
    const token = signToken({ sub: user.id, email: user.email, name: user.name || user.username, role: user.role }, JWT_SECRET, TOKEN_TTL);
    return res.json({ message: "Login correcto", token, expiresIn: TOKEN_TTL, user: publicUser(user) });
  } catch (error) {
    console.error("Error en /login:", error);
    return err(res, 500, "Error interno del servidor");
  }
});

// ==========================================
// MI CUENTA
// ==========================================
app.get("/me", requireAuth, async (req, res) => {
  try {
    const u = await findById(req.auth.sub);
    if (!u) return err(res, 404, "La cuenta ya no existe");
    if (!u.active) return err(res, 403, "Tu cuenta está desactivada. Contacta al administrador.", { code: "account_disabled" });
    res.json(publicUser(u, u.active));
  } catch (e) { console.error(e); err(res, 500, "Error consultando la cuenta"); }
});

app.post("/me/password", requireAuth, async (req, res) => {
  try {
    const { current_password, new_password } = req.body;
    if (!current_password || !new_password) return err(res, 400, "Escribe la contraseña actual y la nueva");
    if (typeof new_password !== "string" || new_password.length < MIN_PASSWORD) {
      return err(res, 400, `La nueva contraseña debe tener al menos ${MIN_PASSWORD} caracteres`);
    }
    const u = await findById(req.auth.sub);
    if (!u) return err(res, 404, "La cuenta ya no existe");
    if (!(await bcrypt.compare(String(current_password), u.password))) {
      return err(res, 400, "La contraseña actual no es correcta");
    }
    await pool.query(`update ${USER_TABLE} set password=$1, "updatedAt"=now() where id=$2`,
      [await bcrypt.hash(new_password, 10), u.id]);
    res.json({ message: "Contraseña actualizada" });
  } catch (e) { console.error(e); err(res, 500, "Error actualizando la contraseña"); }
});

// ==========================================
// GESTIÓN DE USUARIOS (solo administrador)
// ==========================================
app.get("/users", requireAdmin, async (req, res) => {
  try {
    const r = await pool.query(
      `select u.id,u.email,u.username,u.name,u.role,u."createdAt",coalesce(s.active,true) as active
         from ${USER_TABLE} u left join auth_meta.account_status s on s.user_id=u.id
        order by u.id`);
    res.json(r.rows.map((u) => publicUser(u, u.active)));
  } catch (e) { console.error(e); err(res, 500, "Error listando usuarios"); }
});

// Entidades de la cadena (2.5): nombres de las cuentas activas que pueden recibir
// envíos (distribuidores y veterinarias). Cualquier usuario autenticado puede
// consultarla; solo expone nombre y rol (sin correo ni datos sensibles). El
// frontend la usa para elegir el destino de un envío sin escribirlo a mano.
app.get("/entities", requireAuth, async (_req, res) => {
  try {
    const r = await pool.query(
      `select u.name,u.role
         from ${USER_TABLE} u left join auth_meta.account_status s on s.user_id=u.id
        where coalesce(s.active,true) and u.role in ('distribuidor','veterinaria')
          and coalesce(trim(u.name),'') <> ''
        order by u.role, u.name`);
    res.json(r.rows.map((u) => ({ name: u.name, role: u.role })));
  } catch (e) { console.error(e); err(res, 500, "Error listando entidades"); }
});

app.post("/users", requireAdmin, async (req, res) => {
  try {
    const name = typeof req.body.name === "string" ? req.body.name.trim() : "";
    const email = typeof req.body.email === "string" ? req.body.email.trim().toLowerCase() : "";
    const { password, role } = req.body;
    const problem = validateNewUser({ name, email, password, role });
    if (problem) return err(res, 400, problem);
    if (await db.orm.public.User.where({ email }).first()) {
      return err(res, 409, "Ya existe una cuenta con ese correo");
    }
    const user = await createUser({ name, email, password, role });
    console.log(`[auth] usuario creado por ${req.auth.email}: ${email} (${role})`);
    res.status(201).json({ message: "Usuario creado", user: publicUser(user, true) });
  } catch (e) {
    if (e?.code === "23505") return err(res, 409, "Ya existe una cuenta con ese correo");
    console.error("Error en POST /users:", e);
    err(res, 500, "Error creando el usuario");
  }
});

// Cambia rol, nombre o estado (activo/desactivado).
app.patch("/users/:id", requireAdmin, async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!Number.isInteger(id)) return err(res, 400, "Identificador no válido");
    const u = await findById(id);
    if (!u) return err(res, 404, "Usuario no encontrado");
    const self = id === Number(req.auth.sub);
    const { role, name, active } = req.body;

    if (role !== undefined) {
      if (!ROLES.includes(role)) return err(res, 400, `Rol no válido. Roles: ${ROLES.join(", ")}`);
      if (self && role !== "admin") return err(res, 400, "No puedes quitarte el rol de administrador a ti mismo");
    }
    if (active !== undefined) {
      if (typeof active !== "boolean") return err(res, 400, "active debe ser true o false");
      if (self && !active) return err(res, 400, "No puedes desactivar tu propia cuenta");
    }
    if (name !== undefined && !String(name).trim()) return err(res, 400, "El nombre no puede quedar vacío");

    if (role !== undefined || name !== undefined) {
      await pool.query(
        `update ${USER_TABLE} set role=coalesce($1,role), name=coalesce($2,name), "updatedAt"=now() where id=$3`,
        [role ?? null, name !== undefined ? String(name).trim() : null, id]);
    }
    if (active !== undefined) await setActive(id, active);
    const updated = await findById(id);
    res.json({ message: "Usuario actualizado", user: publicUser(updated, updated.active) });
  } catch (e) { console.error(e); err(res, 500, "Error actualizando el usuario"); }
});

// Restablecer contraseña (cuando el usuario la olvidó).
app.post("/users/:id/password", requireAdmin, async (req, res) => {
  try {
    const id = Number(req.params.id);
    const { password } = req.body;
    if (typeof password !== "string" || password.length < MIN_PASSWORD) {
      return err(res, 400, `La contraseña debe tener al menos ${MIN_PASSWORD} caracteres`);
    }
    const r = await pool.query(`update ${USER_TABLE} set password=$1, "updatedAt"=now() where id=$2`,
      [await bcrypt.hash(password, 10), id]);
    if (!r.rowCount) return err(res, 404, "Usuario no encontrado");
    res.json({ message: "Contraseña restablecida" });
  } catch (e) { console.error(e); err(res, 500, "Error restableciendo la contraseña"); }
});

// ==========================================
// REGISTRO PÚBLICO (desactivado por defecto)
// ==========================================
app.post("/register", async (req, res) => {
  if (!ALLOW_SELF_REGISTER) {
    return err(res, 403, "El registro público está desactivado. Pide tu cuenta al administrador.");
  }
  try {
    const name = typeof req.body.name === "string" ? req.body.name.trim() : "";
    const email = typeof req.body.email === "string" ? req.body.email.trim().toLowerCase() : "";
    const { password, role } = req.body;
    if (role === "admin") return err(res, 403, "No se puede crear un administrador desde el registro público");
    const problem = validateNewUser({ name, email, password, role });
    if (problem) return err(res, 400, problem);
    if (await db.orm.public.User.where({ email }).first()) return err(res, 409, "Ya existe una cuenta con ese correo");
    const user = await createUser({ name, email, password, role });
    await setActive(user.id, false); // queda pendiente de aprobación del administrador
    res.status(201).json({ message: "Solicitud registrada. Un administrador debe activar tu cuenta.", user: publicUser(user, false) });
  } catch (e) { console.error(e); err(res, 500, "Error interno del servidor"); }
});

// ==========================================
// DEMO USERS
// ==========================================
async function seedDemoUsers() {
  const users = [
    { email: "admin@vetchain.com", password: "Admin123", name: "Jesús Daniel Garay", role: "admin" },
    { email: "distribuidor@vetchain.com", password: "Dist123", name: "Carlos Ramírez", role: "distribuidor" },
    { email: "veterinaria@vetchain.com", password: "Vet123", name: "María González", role: "veterinaria" },
    { email: "fabricante@vetchain.com", password: "Fab123", name: "Laura Martínez", role: "fabricante" },
  ];
  for (const u of users) {
    const existing = await db.orm.public.User.where({ email: u.email }).first();
    if (!existing) await createUser(u);
  }
}

// ==========================================
// ERRORES (siempre JSON)
// ==========================================
app.use((req, res) => err(res, 404, "Ruta no encontrada"));
app.use((e, req, res, next) => {
  if (res.headersSent) return next(e);
  if (e?.type === "entity.parse.failed") return err(res, 400, "JSON inválido en el cuerpo de la petición");
  console.error(e);
  err(res, 500, "Error interno del servidor");
});

// ==========================================
// START SERVER
// ==========================================
try {
  await initMeta();
} catch (error) {
  console.error("No se pudo preparar la tabla de estado de cuentas:", error.message);
  process.exit(1);
}

if (SEED_DEMO_USERS) {
  try {
    await seedDemoUsers();
    console.log("Usuarios de demostración disponibles (SEED_DEMO_USERS=true).");
  } catch (error) {
    console.error("No se pudieron crear los usuarios de demostración:", error.message);
    console.error("¿Existe la tabla de usuarios? Ejecuta `npx prisma db init` (o simplemente `npm start`).");
    process.exit(1);
  }
} else {
  console.log("Seed de usuarios de demostración desactivado (SEED_DEMO_USERS no es \"true\").");
}

app.listen(PORT, () => {
  console.log(`Auth service running on http://localhost:${PORT}`);
});
