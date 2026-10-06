import express from "express";
import bcrypt from "bcrypt";
import pg from "pg";
import { db } from "./prisma/db.ts";
import { resolveSecret, signToken, verifyToken, bearer } from "./jwt.js";
import { createAudit, clientIp } from "./audit.js";

// =============================================================================
// Auth Service — VetChain 2.7
//
// Novedades 2.7 (corrección de vulnerabilidades):
//   - A2: límite de intentos fallidos de login por cuenta (y por IP en el gateway),
//         contraseña mínima de 8 caracteres con letras y números, y el mismo tiempo
//         de respuesta exista o no la cuenta.
//   - A3: cada token lleva la "versión de sesión" de la cuenta. Desactivar la cuenta,
//         cambiar su rol, su nombre o su contraseña incrementa la versión y los tokens
//         anteriores dejan de valer al instante (GET /session lo comprueba).
//   - A1: el nombre de cada cuenta es único (identifica a la entidad en la cadena).
//   - Usuarios de prueba: el recuadro de cuentas demo del login ya no está en el
//         frontend. Se desbloquea con una cuenta de acceso de demostración que NO es
//         un usuario: no recibe token ni puede usar ninguna función del sistema.
//
// Novedades 2.8:
//   - Registro de auditoría (audit.js): quién hizo qué y cuándo, consultable por el admin.
//   - Foto de perfil: cada usuario puede adjuntar una imagen desde su equipo.
//
// Historia (2.4):
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
const MIN_PASSWORD = 8;
const flag = (v) => String(v || "").trim().toLowerCase() === "true";
const SEED_DEMO_USERS = flag(process.env.SEED_DEMO_USERS);
// Registro público: desactivado. Las cuentas las crea el administrador.
const ALLOW_SELF_REGISTER = String(process.env.ALLOW_SELF_REGISTER || "").trim().toLowerCase() === "true";

const pool = new pg.Pool({ connectionString: process.env.DATABASE_URL, max: Number(process.env.DB_POOL_MAX) || 5 });
pool.on("error", (e) => console.error("[db] error en una conexión inactiva:", e.message));
const USER_TABLE = 'public."user"';

app.disable("x-powered-by");
app.use(express.json({ limit: "300kb" })); // 2.8: la foto de perfil viaja en el cuerpo
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
  photo: u.photo ?? null,
});

const audit = createAudit(pool);

// -----------------------------------------------------------------------------
// Estado de la cuenta (activa / desactivada) y versión de sesión (2.7)
// -----------------------------------------------------------------------------
async function initMeta() {
  await pool.query(`
    CREATE SCHEMA IF NOT EXISTS auth_meta;
    CREATE TABLE IF NOT EXISTS auth_meta.account_status(
      user_id INT PRIMARY KEY,
      active BOOLEAN NOT NULL DEFAULT true,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now());
    ALTER TABLE auth_meta.account_status ADD COLUMN IF NOT EXISTS token_version INT NOT NULL DEFAULT 0;
    CREATE TABLE IF NOT EXISTS auth_meta.profile_photo(
      user_id INT PRIMARY KEY,
      data_url TEXT NOT NULL,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now());`);
  await audit.init();
}

async function setActive(userId, active) {
  await pool.query(
    `insert into auth_meta.account_status(user_id,active) values($1,$2)
     on conflict(user_id) do update set active=excluded.active, updated_at=now()`,
    [userId, active]);
}

// Invalida todos los tokens emitidos hasta ahora para la cuenta (A3).
async function revokeSessions(userId) {
  await pool.query(
    `insert into auth_meta.account_status(user_id,token_version) values($1,1)
     on conflict(user_id) do update set token_version=auth_meta.account_status.token_version+1, updated_at=now()`,
    [userId]);
}

// withPhoto=false en la comprobación de sesión (se hace en cada petición): la foto
// solo se lee cuando hay que devolverla.
async function findById(id, { withPhoto = false } = {}) {
  const r = await pool.query(
    `select u.id,u.email,u.username,u.name,u.role,u.password,u."createdAt",
            coalesce(s.active,true) as active, coalesce(s.token_version,0) as token_version
            ${withPhoto ? ", (select data_url from auth_meta.profile_photo ph where ph.user_id=u.id) as photo" : ""}
       from ${USER_TABLE} u left join auth_meta.account_status s on s.user_id=u.id
      where u.id=$1`, [id]);
  return r.rows[0] || null;
}

const issueToken = (u) => signToken(
  { sub: u.id, email: u.email, name: u.name || u.username, role: u.role, ver: Number(u.token_version) || 0 },
  JWT_SECRET, TOKEN_TTL);

// ¿Hay otra cuenta con ese nombre? (sin distinguir mayúsculas ni espacios)
async function nameTaken(name, exceptId = null) {
  const r = await pool.query(
    `select 1 from ${USER_TABLE} where lower(trim(name))=lower(trim($1)) and ($2::int is null or id<>$2) limit 1`,
    [name, exceptId]);
  return r.rowCount > 0;
}

// -----------------------------------------------------------------------------
// Límite de intentos fallidos de login (A2)
// MAX_LOGIN_FAILURES fallos seguidos en LOGIN_WINDOW_MINUTES bloquean la cuenta
// durante el resto de esa ventana. Un login correcto reinicia el contador.
// -----------------------------------------------------------------------------
const MAX_LOGIN_FAILURES = Number(process.env.MAX_LOGIN_FAILURES) || 5;
const LOGIN_WINDOW_MS = (Number(process.env.LOGIN_WINDOW_MINUTES) || 15) * 60_000;
const loginFailures = new Map(); // identificador -> { count, first }

function lockedForMs(key) {
  const f = loginFailures.get(key);
  if (!f) return 0;
  const left = f.first + LOGIN_WINDOW_MS - Date.now();
  if (left <= 0) { loginFailures.delete(key); return 0; }
  return f.count >= MAX_LOGIN_FAILURES ? left : 0;
}
function registerFailure(key) {
  const f = loginFailures.get(key);
  if (!f || f.first + LOGIN_WINDOW_MS <= Date.now()) loginFailures.set(key, { count: 1, first: Date.now() });
  else f.count++;
  if (loginFailures.size > 10000) loginFailures.clear();
}
const tooManyAttempts = (res, ms) => {
  const minutes = Math.max(1, Math.ceil(ms / 60_000));
  res.set("Retry-After", String(Math.ceil(ms / 1000)));
  return err(res, 429, `Demasiados intentos fallidos. Por seguridad, espera ${minutes} minuto(s) antes de volver a intentarlo.`, { code: "too_many_attempts" });
};

// Hash fijo para comparar cuando la cuenta no existe: así la respuesta tarda lo
// mismo y no revela qué correos están registrados.
const DUMMY_HASH = bcrypt.hashSync("vetchain-cuenta-inexistente", 10);

// -----------------------------------------------------------------------------
// Validaciones compartidas
// -----------------------------------------------------------------------------
// Contraseña: al menos MIN_PASSWORD caracteres, con letras y números (A2).
function passwordProblem(password) {
  if (typeof password !== "string" || password.length < MIN_PASSWORD) {
    return `La contraseña debe tener al menos ${MIN_PASSWORD} caracteres`;
  }
  if (password.length > 128) return "La contraseña no puede superar 128 caracteres";
  if (!/[A-Za-zÁÉÍÓÚÑáéíóúñ]/.test(password) || !/\d/.test(password)) {
    return "La contraseña debe combinar letras y números";
  }
  return null;
}

const MAX_NAME = 120;
function validateNewUser({ name, email, password, role }) {
  if (!name || !String(name).trim()) return "El nombre es obligatorio";
  if (String(name).trim().length > MAX_NAME) return `El nombre no puede superar ${MAX_NAME} caracteres`;
  if (!email) return "El correo es obligatorio";
  if (email.length > 254 || !EMAIL_RE.test(email)) return "El correo no tiene un formato válido";
  if (isDemoAccessEmail(email)) return "Ese correo está reservado para el acceso de demostración";
  const pw = passwordProblem(password);
  if (pw) return pw;
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
// 2.7: además de la firma, comprueba en la base que la sesión sigue vigente:
// la cuenta existe y está activa, y el rol y la versión de sesión del token
// coinciden con los actuales. Si no, el token quedó revocado (A3).
// Uso de un token revocado (cuenta cambiada): se registra una vez por token cada 5 min,
// porque el gateway y los servicios consultan la sesión varias veces.
const revokedSeen = new Map();
function logRevokedUse(req, payload) {
  const key = String(bearer(req)).slice(-43);
  if (Date.now() - (revokedSeen.get(key) || 0) < 5 * 60_000) return;
  revokedSeen.set(key, Date.now());
  if (revokedSeen.size > 5000) revokedSeen.clear();
  audit.record({ actor_id: payload.sub, actor_name: payload.name, actor_role: payload.role, action: "session.revoked_use",
    outcome: "denied", severity: "warning", ip: clientIp(req), message: "Se usó un token revocado (la cuenta cambió de rol, nombre, contraseña o estado)" });
}

async function requireAuth(req, res, next) {
  const payload = verifyToken(bearer(req), JWT_SECRET);
  if (!payload) return err(res, 401, "Sesión no válida o expirada. Inicia sesión de nuevo.");
  try {
    const u = await findById(Number(payload.sub));
    if (!u) return err(res, 401, "La cuenta ya no existe.", { code: "session_revoked" });
    if (!u.active) return err(res, 401, "Tu cuenta está desactivada. Contacta al administrador.", { code: "account_disabled" });
    if (u.role !== payload.role || Number(u.token_version) !== Number(payload.ver ?? -1)) {
      logRevokedUse(req, payload);
      return err(res, 401, "Tu sesión se cerró porque tu cuenta cambió (rol, nombre o contraseña). Inicia sesión de nuevo.", { code: "session_revoked" });
    }
    req.auth = payload;
    req.account = u;
    next();
  } catch (e) {
    console.error("Error validando la sesión:", e.message);
    err(res, 503, "No se pudo validar la sesión. Intenta de nuevo en unos segundos.");
  }
}
function requireAdmin(req, res, next) {
  return requireAuth(req, res, () => {
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
    if ([identifier, email, username, password].some((v) => v !== undefined && typeof v !== "string")
        || String(password).length > 128) {
      return err(res, 400, "Correo o contraseña con formato no válido");
    }
    const key = String(identifier || email || username).trim().toLowerCase();
    const locked = lockedForMs(key);
    const ip = clientIp(req);
    if (locked) {
      const who = await findUserForLogin({ identifier, email, username }).catch(() => null);
      audit.record({ actor_id: who?.id ?? null, actor_name: who ? (who.name || who.username) : key, actor_role: who?.role ?? null, action: "login.locked", outcome: "blocked", severity: "critical", ip, target: key,
        message: `Intento de inicio de sesión con la cuenta bloqueada por ${MAX_LOGIN_FAILURES} fallos seguidos` });
      return tooManyAttempts(res, locked);
    }

    // Acceso de demostración: desbloquea el recuadro de Usuarios de prueba.
    if (isDemoAccessEmail(key)) return demoAccessLogin(req, res, key, String(password));

    const user = await findUserForLogin({ identifier, email, username });
    // Mismo mensaje y mismo tiempo si no existe o si la contraseña no coincide.
    const valid = await bcrypt.compare(String(password), user ? user.password : DUMMY_HASH);
    if (!user || !valid) {
      registerFailure(key);
      const nowLocked = lockedForMs(key) > 0;
      audit.record({ actor_id: user?.id ?? null, actor_name: user ? (user.name || user.username) : key, actor_role: user?.role ?? null,
        action: "login.failed", outcome: nowLocked ? "blocked" : "failed", severity: nowLocked ? "critical" : "warning", ip, target: key,
        message: nowLocked ? `Contraseña incorrecta: la cuenta queda bloqueada ${Math.round(LOGIN_WINDOW_MS / 60000)} min`
          : user ? "Contraseña incorrecta" : "Correo no registrado" });
      return err(res, 401, "Correo o contraseña incorrectos");
    }
    loginFailures.delete(key);
    const account = await findById(user.id, { withPhoto: true });
    if (!account.active) {
      audit.record({ actor_id: account.id, actor_name: account.name, actor_role: account.role, action: "login.disabled", outcome: "denied", severity: "warning", ip, target: key, message: "Intento de inicio de sesión con una cuenta desactivada" });
      return err(res, 403, "Tu cuenta está desactivada. Contacta al administrador.", { code: "account_disabled" });
    }
    if (!ROLES.includes(account.role)) {
      return err(res, 403, "Tu cuenta no tiene un rol asignado. Pide al administrador que te asigne uno.", { code: "no_role" });
    }
    audit.record({ actor_id: account.id, actor_name: account.name, actor_role: account.role, action: "login.success", outcome: "ok", severity: "info", ip, target: key, message: "Inicio de sesión" });
    return res.json({ message: "Login correcto", token: issueToken(account), expiresIn: TOKEN_TTL, user: publicUser(account) });
  } catch (error) {
    console.error("Error en /login:", error);
    return err(res, 500, "Error interno del servidor");
  }
});

// ==========================================
// MI CUENTA
// ==========================================
app.get("/me", requireAuth, async (req, res) => {
  const u = await findById(req.account.id, { withPhoto: true });
  res.json(publicUser(u, u.active));
});

// Usada por el gateway y por los microservicios para saber si un token sigue vigente.
app.get("/session", requireAuth, (req, res) => res.json({ ok: true, role: req.account.role }));

app.post("/me/password", requireAuth, async (req, res) => {
  try {
    const { current_password, new_password } = req.body;
    if (!current_password || !new_password) return err(res, 400, "Escribe la contraseña actual y la nueva");
    const pw = passwordProblem(new_password);
    if (pw) return err(res, 400, pw.replace("La contraseña", "La nueva contraseña"));
    const u = req.account;
    if (!(await bcrypt.compare(String(current_password), u.password))) {
      audit.fromReq(req, { action: "password.change_failed", outcome: "failed", severity: "warning", message: "Contraseña actual incorrecta al intentar cambiarla" });
      return err(res, 400, "La contraseña actual no es correcta");
    }
    await pool.query(`update ${USER_TABLE} set password=$1, "updatedAt"=now() where id=$2`,
      [await bcrypt.hash(new_password, 10), u.id]);
    // Cierra las demás sesiones de la cuenta y entrega un token nuevo para esta (A3).
    await revokeSessions(u.id);
    const fresh = await findById(u.id, { withPhoto: true });
    audit.fromReq(req, { action: "password.changed", outcome: "ok", severity: "info", message: "Cambió su contraseña (se cerraron sus otras sesiones)" });
    res.json({ message: "Contraseña actualizada", token: issueToken(fresh), expiresIn: TOKEN_TTL, user: publicUser(fresh) });
  } catch (e) { console.error(e); err(res, 500, "Error actualizando la contraseña"); }
});

// ==========================================
// GESTIÓN DE USUARIOS (solo administrador)
// ==========================================
app.get("/users", requireAdmin, async (req, res) => {
  try {
    const r = await pool.query(
      `select u.id,u.email,u.username,u.name,u.role,u."createdAt",coalesce(s.active,true) as active, ph.data_url as photo
         from ${USER_TABLE} u left join auth_meta.account_status s on s.user_id=u.id
         left join auth_meta.profile_photo ph on ph.user_id=u.id
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
    if (await nameTaken(name)) return err(res, 409, "Ya existe una cuenta con ese nombre. El nombre identifica a la entidad en la cadena: usa uno distinto.");
    const user = await createUser({ name, email, password, role });
    console.log(`[auth] usuario creado por ${req.auth.email}: ${email} (${role})`);
    audit.fromReq(req, { action: "user.created", outcome: "ok", severity: "info", target: `${name} <${email}>`, message: `Creó la cuenta de ${name} con rol ${role}`, details: { role } });
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
    if (name !== undefined) {
      if (typeof name !== "string" || !name.trim()) return err(res, 400, "El nombre no puede quedar vacío");
      if (name.trim().length > MAX_NAME) return err(res, 400, `El nombre no puede superar ${MAX_NAME} caracteres`);
      if (await nameTaken(name, id)) return err(res, 409, "Ya existe otra cuenta con ese nombre");
    }

    const roleChanged = role !== undefined && role !== u.role;
    const nameChanged = name !== undefined && name.trim() !== (u.name || "");
    const deactivated = active === false && u.active;
    if (role !== undefined || name !== undefined) {
      await pool.query(
        `update ${USER_TABLE} set role=coalesce($1,role), name=coalesce($2,name), "updatedAt"=now() where id=$3`,
        [role ?? null, name !== undefined ? name.trim() : null, id]);
    }
    if (active !== undefined) await setActive(id, active);
    // El token lleva rol y nombre: si cambian, o si la cuenta se desactiva, los
    // tokens anteriores dejan de valer (A3).
    if (roleChanged || nameChanged || deactivated) await revokeSessions(id);
    const updated = await findById(id, { withPhoto: true });
    const changes = [];
    if (roleChanged) changes.push(`rol ${u.role} → ${role}`);
    if (nameChanged) changes.push(`nombre "${u.name}" → "${name.trim()}"`);
    if (active !== undefined && active !== u.active) changes.push(active ? "cuenta reactivada" : "cuenta desactivada");
    if (changes.length) {
      audit.fromReq(req, { action: deactivated ? "user.deactivated" : roleChanged ? "user.role_changed" : "user.updated", outcome: "ok",
        severity: deactivated || roleChanged ? "warning" : "info", target: `${updated.name} <${updated.email}>`, message: `Modificó la cuenta: ${changes.join(", ")}`,
        details: { roleChanged, nameChanged, active: updated.active } });
    }
    res.json({ message: "Usuario actualizado", user: publicUser(updated, updated.active) });
  } catch (e) { console.error(e); err(res, 500, "Error actualizando el usuario"); }
});

// Restablecer contraseña (cuando el usuario la olvidó).
app.post("/users/:id/password", requireAdmin, async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!Number.isInteger(id)) return err(res, 400, "Identificador no válido");
    const { password } = req.body;
    const pw = passwordProblem(password);
    if (pw) return err(res, 400, pw);
    const r = await pool.query(`update ${USER_TABLE} set password=$1, "updatedAt"=now() where id=$2`,
      [await bcrypt.hash(password, 10), id]);
    if (!r.rowCount) return err(res, 404, "Usuario no encontrado");
    await revokeSessions(id); // cierra las sesiones abiertas con la contraseña anterior (A3)
    const target = await findById(id);
    audit.fromReq(req, { action: "user.password_reset", outcome: "ok", severity: "warning", target: `${target?.name} <${target?.email}>`, message: "Restableció la contraseña de la cuenta" });
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
    if (await nameTaken(name)) return err(res, 409, "Ya existe una cuenta con ese nombre");
    const user = await createUser({ name, email, password, role });
    await setActive(user.id, false); // queda pendiente de aprobación del administrador
    res.status(201).json({ message: "Solicitud registrada. Un administrador debe activar tu cuenta.", user: publicUser(user, false) });
  } catch (e) { console.error(e); err(res, 500, "Error interno del servidor"); }
});

// ==========================================
// USUARIOS DE PRUEBA (solo entorno de demostración)
// ==========================================
// Cuentas ficticias para explorar el sistema. Se crean solo con SEED_DEMO_USERS=true.
const DEMO_USERS = [
  { email: "admin@vetchain.com", password: "Admin123", name: "Jesús Daniel Garay", role: "admin" },
  { email: "fabricante@vetchain.com", password: "Fab123", name: "Laura Martínez", role: "fabricante" },
  { email: "distribuidor@vetchain.com", password: "Dist123", name: "Carlos Ramírez", role: "distribuidor" },
  { email: "veterinaria@vetchain.com", password: "Vet123", name: "María González", role: "veterinaria" },
];

async function seedDemoUsers() {
  for (const u of DEMO_USERS) {
    const existing = await db.orm.public.User.where({ email: u.email }).first();
    if (!existing) await createUser(u);
  }
}

// Acceso de demostración (2.7)
// El recuadro "Usuarios de prueba" del login está bloqueado. Se desbloquea al
// iniciar sesión con DEMO_ACCESS_EMAIL / DEMO_ACCESS_PASSWORD. Medidas para que
// este mecanismo no sea una vía de acceso al sistema real:
//   - Solo existe si DEMO_ACCESS está activo (por defecto, igual que SEED_DEMO_USERS).
//     Desactivado, esas credenciales se tratan como cualquier cuenta inexistente.
//   - NO es un usuario: no está en la tabla de usuarios, no tiene rol y la respuesta
//     no incluye token. Con ella no se puede llamar a ninguna ruta del sistema.
//   - Su correo está reservado: nadie puede registrar una cuenta con él.
//   - Comparte el límite de intentos fallidos del login.
//   - Solo devuelve las cuentas demo que existen, están activas y conservan su
//     contraseña de demostración (si el admin la cambió, esa cuenta no se muestra).
const DEMO_ACCESS = process.env.DEMO_ACCESS !== undefined ? flag(process.env.DEMO_ACCESS) : SEED_DEMO_USERS;
const DEMO_ACCESS_EMAIL = (process.env.DEMO_ACCESS_EMAIL || "usuariosdeprueba@vetchain").trim().toLowerCase();
const DEMO_ACCESS_HASH = DEMO_ACCESS ? bcrypt.hashSync(process.env.DEMO_ACCESS_PASSWORD || "Usuarios_Prueba123", 10) : null;
const DEMO_LABEL = { admin: "Administrador", fabricante: "Fabricante", distribuidor: "Distribuidor", veterinaria: "Veterinaria" };

function isDemoAccessEmail(value) {
  return String(value || "").trim().toLowerCase() === DEMO_ACCESS_EMAIL;
}

async function demoAccessLogin(req, res, key, password) {
  const valid = await bcrypt.compare(password, DEMO_ACCESS_HASH || DUMMY_HASH);
  if (!DEMO_ACCESS || !valid) {
    registerFailure(key);
    audit.record({ actor_name: "Acceso de demostración", action: "demo.failed", outcome: lockedForMs(key) ? "blocked" : "failed",
      severity: "warning", ip: clientIp(req), target: key, message: DEMO_ACCESS ? "Contraseña incorrecta del acceso de demostración" : "Intento de usar el acceso de demostración con el modo demo desactivado" });
    return err(res, 401, "Correo o contraseña incorrectos");
  }
  loginFailures.delete(key);
  const accounts = [];
  for (const d of DEMO_USERS) {
    const u = await db.orm.public.User.where({ email: d.email }).first();
    if (!u) continue;
    const acc = await findById(u.id);
    if (!acc?.active || !(await bcrypt.compare(d.password, acc.password))) continue;
    accounts.push({ email: d.email, password: d.password, role: acc.role, label: DEMO_LABEL[acc.role] || acc.role, name: acc.name });
  }
  console.log(`[auth] módulo de Usuarios de prueba desbloqueado (${accounts.length} cuentas disponibles)`);
  audit.record({ actor_name: "Acceso de demostración", action: "demo.unlocked", outcome: "ok", severity: "info", ip: clientIp(req), target: key, message: `Desbloqueó los Usuarios de prueba (${accounts.length} cuentas)` });
  return res.json({
    demoAccess: true,
    message: "Usuarios de prueba desbloqueados. Son cuentas ficticias, solo para demostración.",
    accounts,
  });
}

// ==========================================
// FOTO DE PERFIL (2.8)
// ==========================================
// La imagen llega como data URL (el navegador la recorta y reduce antes de enviarla).
// Validaciones: solo JPEG, PNG o WebP (no SVG: podría llevar código), base64 válido,
// máximo PHOTO_MAX_KB y la "firma" de los primeros bytes debe coincidir con el tipo
// declarado (un archivo renombrado no pasa).
const PHOTO_MAX_KB = Number(process.env.PHOTO_MAX_KB) || 200;
const PHOTO_RE = /^data:(image\/(?:jpeg|png|webp));base64,([A-Za-z0-9+/]+={0,2})$/;
function photoProblem(dataUrl) {
  if (typeof dataUrl !== "string") return "Adjunta una imagen";
  const m = PHOTO_RE.exec(dataUrl);
  if (!m) return "Formato no permitido: usa una imagen JPG, PNG o WebP";
  const bytes = Buffer.from(m[2], "base64");
  if (!bytes.length) return "La imagen está vacía";
  if (bytes.length > PHOTO_MAX_KB * 1024) return `La imagen supera ${PHOTO_MAX_KB} KB`;
  const sig = {
    "image/jpeg": bytes[0] === 0xff && bytes[1] === 0xd8 && bytes[2] === 0xff,
    "image/png": bytes.subarray(0, 8).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a])),
    "image/webp": bytes.subarray(0, 4).toString("ascii") === "RIFF" && bytes.subarray(8, 12).toString("ascii") === "WEBP",
  }[m[1]];
  if (!sig) return "El contenido del archivo no corresponde a una imagen válida";
  return null;
}
async function savePhoto(userId, dataUrl) {
  await pool.query(
    `insert into auth_meta.profile_photo(user_id,data_url) values($1,$2)
     on conflict(user_id) do update set data_url=excluded.data_url, updated_at=now()`, [userId, dataUrl]);
}

app.post("/me/photo", requireAuth, async (req, res) => {
  try {
    const problem = photoProblem(req.body.image);
    if (problem) {
      audit.fromReq(req, { action: "profile.photo_rejected", outcome: "rejected", severity: "warning", message: `Foto rechazada: ${problem}` });
      return err(res, 400, problem);
    }
    await savePhoto(req.account.id, req.body.image);
    audit.fromReq(req, { action: "profile.photo_updated", outcome: "ok", severity: "info", message: "Actualizó su foto de perfil" });
    res.json({ message: "Foto de perfil actualizada", photo: req.body.image });
  } catch (e) { console.error(e); err(res, 500, "Error guardando la foto"); }
});

app.delete("/me/photo", requireAuth, async (req, res) => {
  try {
    await pool.query("delete from auth_meta.profile_photo where user_id=$1", [req.account.id]);
    audit.fromReq(req, { action: "profile.photo_removed", outcome: "ok", severity: "info", message: "Quitó su foto de perfil" });
    res.json({ message: "Foto de perfil eliminada", photo: null });
  } catch (e) { console.error(e); err(res, 500, "Error eliminando la foto"); }
});

// El administrador puede retirar una foto inapropiada.
app.delete("/users/:id/photo", requireAdmin, async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!Number.isInteger(id)) return err(res, 400, "Identificador no válido");
    const u = await findById(id);
    if (!u) return err(res, 404, "Usuario no encontrado");
    await pool.query("delete from auth_meta.profile_photo where user_id=$1", [id]);
    audit.fromReq(req, { action: "profile.photo_removed_by_admin", outcome: "ok", severity: "warning", target: `${u.name} <${u.email}>`, message: "Retiró la foto de perfil de la cuenta" });
    res.json({ message: "Foto retirada" });
  } catch (e) { console.error(e); err(res, 500, "Error retirando la foto"); }
});

// ==========================================
// AUDITORÍA (2.8)
// ==========================================
app.get("/audit", requireAdmin, (req, res) => audit.list(req, res));
// Eventos firmados del gateway y los microservicios (no está publicada en el gateway).
app.post("/internal/audit", audit.internalHandler(JWT_SECRET));

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

console.log(`Acceso de demostración (Usuarios de prueba): ${DEMO_ACCESS ? "activo" : "desactivado"}.`);
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
