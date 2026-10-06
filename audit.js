// =============================================================================
// Registro de auditoría (VetChain 2.8)
//
// Guarda quién hizo qué y cuándo: inicios de sesión, intentos fallidos y bloqueados,
// accesos denegados, cambios de usuarios y operaciones de la cadena (lotes, envíos,
// dispensaciones, recalls). Vive en auth-service (tabla auth_meta.audit_log).
//
// - auth-service escribe sus propios eventos directamente (record).
// - El gateway y los demás microservicios los envían a POST /internal/audit firmados
//   con HMAC-SHA256 usando JWT_SECRET (cabeceras X-Audit-Ts y X-Audit-Signature).
//   Sin firma válida (o con más de 5 minutos de antigüedad) se rechaza: nadie de
//   fuera puede inventar o borrar entradas. El gateway no expone /auth/internal.
// - Solo el administrador puede leerlo (GET /audit). No hay ruta para modificarlo.
// =============================================================================
import crypto from "crypto";

export const AUDIT_OUTCOMES = ["ok", "failed", "denied", "blocked", "rejected"];
export const AUDIT_SEVERITIES = ["info", "warning", "critical"];
const RETENTION_DAYS = Number(process.env.AUDIT_RETENTION_DAYS) || 90;
const MAX_SKEW_MS = 5 * 60_000;

const cut = (v, n) => (v === undefined || v === null ? null : String(v).slice(0, n));

export function clientIp(req) {
  const xff = String(req.headers["x-forwarded-for"] || "").split(",")[0].trim();
  const ip = xff || req.socket?.remoteAddress || "";
  return ip.replace(/^::ffff:/, "") || null;
}

export function signAudit(secret, ts, body) {
  return crypto.createHmac("sha256", secret).update(`${ts}.${body}`).digest("hex");
}

export function createAudit(pool) {
  let inserts = 0;
  const forgedSeen = new Map();

  async function init() {
    await pool.query(`
      CREATE SCHEMA IF NOT EXISTS auth_meta;
      CREATE TABLE IF NOT EXISTS auth_meta.audit_log(
        id BIGSERIAL PRIMARY KEY,
        at TIMESTAMPTZ NOT NULL DEFAULT now(),
        actor_id INT,
        actor_name TEXT,
        actor_role TEXT,
        action TEXT NOT NULL,
        outcome TEXT NOT NULL,
        severity TEXT NOT NULL,
        service TEXT,
        ip TEXT,
        method TEXT,
        path TEXT,
        target TEXT,
        message TEXT,
        details JSONB);
      CREATE INDEX IF NOT EXISTS idx_audit_at ON auth_meta.audit_log(at DESC);`);
  }

  // Nunca lanza: un fallo de auditoría no debe tumbar la operación principal.
  async function record(ev) {
    try {
      const outcome = AUDIT_OUTCOMES.includes(ev.outcome) ? ev.outcome : "ok";
      const severity = AUDIT_SEVERITIES.includes(ev.severity) ? ev.severity : "info";
      await pool.query(
        `insert into auth_meta.audit_log(actor_id,actor_name,actor_role,action,outcome,severity,service,ip,method,path,target,message,details)
         values($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`,
        [Number.isInteger(Number(ev.actor_id)) && ev.actor_id !== null && ev.actor_id !== undefined ? Number(ev.actor_id) : null,
          cut(ev.actor_name, 160), cut(ev.actor_role, 20), cut(ev.action, 64), outcome, severity,
          cut(ev.service || "auth", 30), cut(ev.ip, 64), cut(ev.method, 10), cut(ev.path, 200),
          cut(ev.target, 200), cut(ev.message, 300), ev.details && typeof ev.details === "object" ? ev.details : null]);
      if (++inserts % 500 === 0) {
        await pool.query(`delete from auth_meta.audit_log where at < now() - ($1 || ' days')::interval`, [String(RETENTION_DAYS)]);
      }
    } catch (e) {
      console.error("[audit] no se pudo registrar el evento:", e.message);
    }
  }

  // Evento a partir de una petición (actor = sesión si la hay).
  const fromReq = (req, ev) => record({
    actor_id: req.auth?.sub ?? null, actor_name: req.auth?.name ?? null, actor_role: req.auth?.role ?? null,
    ip: clientIp(req), method: req.method, path: req.originalUrl?.split("?")[0], ...ev,
  });

  // POST /internal/audit — eventos firmados que envían el gateway y los microservicios.
  function internalHandler(secret) {
    return async (req, res) => {
      const ts = Number(req.headers["x-audit-ts"]);
      const given = String(req.headers["x-audit-signature"] || "");
      const body = JSON.stringify(req.body || {});
      const expected = signAudit(secret, ts, body);
      const ok = Number.isFinite(ts) && Math.abs(Date.now() - ts) <= MAX_SKEW_MS
        && given.length === expected.length && crypto.timingSafeEqual(Buffer.from(given), Buffer.from(expected));
      if (!ok) {
        // Se registra como máximo un intento falsificado por IP y minuto (evita llenar la tabla).
        const ip = clientIp(req) || "?";
        const last = forgedSeen.get(ip) || 0;
        if (Date.now() - last > 60_000) { forgedSeen.set(ip, Date.now()); if (forgedSeen.size > 5000) forgedSeen.clear(); } else return res.status(401).json({ error: "Firma de auditoría no válida" });
        await fromReq(req, { action: "audit.forged", outcome: "denied", severity: "critical", message: "Intento de escribir en la auditoría sin firma válida" });
        return res.status(401).json({ error: "Firma de auditoría no válida" });
      }
      const ev = req.body || {};
      if (typeof ev.action !== "string" || !/^[a-z_.]{3,64}$/.test(ev.action)) return res.status(400).json({ error: "Evento no válido" });
      await record(ev);
      res.status(201).json({ ok: true });
    };
  }

  // GET /audit — últimos eventos y resumen de las últimas 24 h (solo administrador).
  async function list(req, res) {
    try {
      const limit = Math.min(Math.max(parseInt(req.query.limit, 10) || 500, 1), 2000);
      const rows = (await pool.query(
        `select id,at,actor_id,actor_name,actor_role,action,outcome,severity,service,ip,method,path,target,message,details
           from auth_meta.audit_log order by at desc, id desc limit $1`, [limit])).rows;
      const s = (await pool.query(
        `select
           count(*) filter (where action='login.success')::int as logins_ok,
           count(*) filter (where action in ('login.failed','demo.failed'))::int as logins_failed,
           count(*) filter (where outcome='blocked')::int as blocked,
           count(*) filter (where outcome='denied')::int as denied,
           count(*) filter (where severity='critical')::int as critical,
           count(*)::int as total
         from auth_meta.audit_log where at > now() - interval '24 hours'`)).rows[0];
      res.json({ summary: s, events: rows });
    } catch (e) {
      console.error(e);
      res.status(500).json({ error: "Error consultando la auditoría" });
    }
  }

  return { init, record, fromReq, internalHandler, list };
}
