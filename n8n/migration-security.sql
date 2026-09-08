-- ============================================================================
-- Migración de seguridad para AgendaOS — aplicar ANTES de importar
-- workflow-fixed.json. Ejecutar en orden, revisando cada bloque.
-- ============================================================================

-- 1) Hash de contraseñas: agrega la columna nueva sin tocar la vieja todavía.
ALTER TABLE negocios ADD COLUMN IF NOT EXISTS password_hash TEXT;

-- 2) Idempotencia de pagos MercadoPago.
CREATE TABLE IF NOT EXISTS pagos_procesados (
  payment_id TEXT PRIMARY KEY,
  org_id TEXT NOT NULL,
  procesado_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- 3) Recordatorios de WhatsApp: columnas para no reenviar el mismo mensaje.
ALTER TABLE reservas
  ADD COLUMN IF NOT EXISTS recordatorio_24h_enviado BOOLEAN NOT NULL DEFAULT FALSE,
  ADD COLUMN IF NOT EXISTS recordatorio_2h_enviado  BOOLEAN NOT NULL DEFAULT FALSE;

-- 4) Índices que probablemente ya deberías tener si no existen (WHERE org_id
--    aparece en absolutamente todas las queries del workflow).
CREATE INDEX IF NOT EXISTS idx_reservas_org_fecha ON reservas(org_id, fecha_inicio);
CREATE INDEX IF NOT EXISTS idx_clientes_org_tel ON clientes(org_id, telefono);
CREATE INDEX IF NOT EXISTS idx_movimientos_org_fecha ON movimientos(org_id, fecha DESC);
CREATE INDEX IF NOT EXISTS idx_servicios_org ON servicios(org_id);
CREATE INDEX IF NOT EXISTS idx_profesionales_org ON profesionales(org_id);
CREATE INDEX IF NOT EXISTS idx_productos_org ON productos(org_id);

-- ============================================================================
-- PASO MANUAL — no lo corras como script, es una migración de datos real:
--
-- Las contraseñas existentes están en texto plano en la columna `password`.
-- Necesitas una corrida ÚNICA que las lea, las hashee con crypto.scryptSync
-- (mismo algoritmo que ahora usa el workflow) y llene `password_hash`.
--
-- Opción simple: en n8n, crea un workflow manual de un solo uso:
--   1. Postgres: SELECT org_id, password FROM negocios WHERE password_hash IS NULL;
--   2. Code node:
--        const crypto = require('crypto');
--        return $input.all().map(i => {
--          const salt = crypto.randomBytes(16).toString('hex');
--          const hash = crypto.scryptSync(i.json.password, salt, 64).toString('hex');
--          return { json: { org_id: i.json.org_id, password_hash: `${salt}:${hash}` } };
--        });
--   3. Postgres (loop, "Execute once per item"):
--        UPDATE negocios SET password_hash = '{{ $json.password_hash }}' WHERE org_id = '{{ $json.org_id }}';
--
-- Ejecuta ese workflow UNA vez, bórralo, y solo entonces corre:
--
-- ALTER TABLE negocios DROP COLUMN password;
--
-- Hasta que confirmes que TODAS las filas tienen password_hash poblado, NO
-- borres la columna vieja — el login (PG Login del workflow nuevo) ya no lee
-- `password`, así que dejarla ahí un tiempo no rompe nada, solo es limpieza.
-- ============================================================================
