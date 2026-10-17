// =============================================================================
// auth-service — comprobación previa al arranque (VetChain 3.1)
//
// "npm start" la ejecuta ANTES de "prisma db init". Si DATABASE_URL falta o está
// mal pegada, Prisma falla con mensajes poco claros; aquí se explica el problema
// en español en los logs de Render. Nunca imprime la contraseña ni la URL completa.
//   - Error (no arranca): DATABASE_URL vacía, con formato inválido o que no es PostgreSQL.
//   - Aviso (arranca igual): host con "-pooler" o parámetro channel_binding (Neon).
// =============================================================================
const raw = (process.env.DATABASE_URL || "").trim();
const fail = (msg) => {
  console.error(`[auth][preflight] ERROR: ${msg}`);
  console.error("[auth][preflight] Render -> vc-...-auth -> Environment -> DATABASE_URL. Ver DEPLOY-GRATIS.md (Paso 3).");
  process.exit(1);
};

if (!raw) fail("DATABASE_URL no está definida.");
let url;
try { url = new URL(raw); } catch { fail("DATABASE_URL no es una URL válida (¿quedaron comillas o espacios al pegarla?)."); }
if (!/^postgres(ql)?:$/.test(url.protocol)) fail(`DATABASE_URL debe empezar por postgresql:// (empieza por ${url.protocol}//).`);
if (!url.hostname) fail("DATABASE_URL no tiene host.");
if (process.env.NODE_ENV === "production" && /^(localhost|127\.0\.0\.1|postgres)$/.test(url.hostname)) {
  fail(`DATABASE_URL apunta a "${url.hostname}", que solo existe en tu PC/Docker. En Render usa la URL de Neon.`);
}
if (/-pooler\./.test(url.hostname)) {
  console.warn("[auth][preflight] AVISO: el host tiene \"-pooler\". Usa la conexión DIRECTA de Neon (Connection pooling desactivado).");
}
if (url.searchParams.has("channel_binding")) {
  console.warn("[auth][preflight] AVISO: quita \"&channel_binding=require\" de DATABASE_URL; debe terminar en ?sslmode=require.");
}
if (/neon\.tech$/.test(url.hostname) && url.searchParams.get("sslmode") !== "require") {
  console.warn("[auth][preflight] AVISO: Neon exige SSL. Añade ?sslmode=require al final de DATABASE_URL.");
}
console.log(`[auth][preflight] DATABASE_URL ok (host ${url.hostname}, base ${decodeURIComponent(url.pathname.slice(1)) || "(por defecto)"}).`);
