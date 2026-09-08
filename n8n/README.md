# Backend n8n — `workflow-fixed.json`

El frontend (`index.html` / `reservar.html`) vive en este repo; el backend real corre en
n8n (`https://n8n-n8n.fa2cjf.easypanel.host/webhook/...`) y no estaba versionado aquí. Este
directorio ahora contiene una reconstrucción completa y segura de ese workflow — mismos
13 endpoints, mismos paths, el frontend no necesita cambios — generada a partir del export
real que se auditó (ver hallazgos abajo).

- `workflow-fixed.json` — el workflow completo, listo para importar en n8n (**Import from File**).
- `migration-security.sql` — corre esto en Postgres **antes** de importar el workflow.
- `build_workflow.py` — el script que genera `workflow-fixed.json`. Está en el repo para que
  cualquier cambio futuro se haga editando el script (y quede en git), no clickeando nodos
  sueltos en el canvas de n8n. `python3 build_workflow.py` lo regenera y valida (nombres/ids
  únicos, toda conexión apunta a un nodo que existe) antes de escribir el archivo.

## Qué cambió respecto al workflow original

- **`agenda-agente-wa` (el agente de WhatsApp con IA) no tenía ninguna autenticación** —
  cualquiera en internet podía simular un mensaje entrante y hacer que el agente creara/
  cancelara citas o leyera historial de clientes de cualquier negocio. Ahora exige un
  secreto (`WA_AGENT_WEBHOOK_SECRET`) en la URL del webhook.
- **Inyección SQL** en `instancia`/`pushName` (agente WA), `fecha_inicio`/`fecha_fin`
  (reservas) y en el JSON de configuración del negocio — todo saneado antes de tocar SQL.
- **Contraseñas en texto plano** (`negocios.password`, comparadas con `=` en SQL) →
  `crypto.scryptSync` nativo de Node (sin dependencias externas) + comparación con
  `timingSafeEqual`.
- **Sin aislamiento por tenant**: la única credencial era una API key estática igual para
  todos. Ahora el login emite un JWT firmado (`APP_JWT_SECRET`) y cada endpoint privado
  verifica que el `org_id` del token coincida con el del body antes de tocar la base de
  datos. `agenda-servicios`/`agenda-profesionales` (acción `getAll`) y
  `agenda-configuracion` (acción `getPublic`) siguen siendo públicos a propósito — es lo
  que necesita `reservar.html` sin login.
- **Token de MercadoPago hardcodeado dos veces en el JSON** → variable de entorno
  `MP_ACCESS_TOKEN`.
- **Webhook de pago sin idempotencia** → tabla `pagos_procesados`, una notificación
  repetida ya no vuelve a extender el plan.
- **Recordatorios 24h/2h eran un toggle sin efecto** → Schedule Trigger real (`Cada 15
  min`) que respeta esos toggles guardados en `configuracion.datos`.
- Conflicto de horario ahora también se valida en las reservas que crea el agente de WA
  (antes solo lo hacía el endpoint del panel).

## Cómo desplegar

1. **Rota ya** la API key vieja (`AUTIX-2025-xK9mP3qR8nL7`) y el Access Token de
   MercadoPago si en algún momento quedaron expuestos fuera de n8n — ambos están fuera
   del JSON ahora, pero si ya circularon, un valor nuevo es la única forma de invalidar
   el viejo.
2. Corre `migration-security.sql` contra tu Postgres.
3. En n8n/EasyPanel, define estas variables de entorno:
   - `AUTIX_API_KEY` — la API key nueva (reemplaza a la hardcodeada).
   - `APP_JWT_SECRET` — `openssl rand -hex 32`.
   - `N8N_INTERNAL_KEY` — `openssl rand -hex 32` (usada solo entre `agenda-public-booking`
     y `agenda-reservas` para que una reserva pública pueda crearse sin sesión de usuario).
   - `MP_ACCESS_TOKEN` — el Access Token de MercadoPago (rotado).
   - `WA_AGENT_WEBHOOK_SECRET` — string largo aleatorio.
   - `ANTHROPIC_API_KEY` — fallback si un negocio no configuró su propia key.
4. Importa `workflow-fixed.json` en n8n (como workflow nuevo o reemplazando el actual —
   recomendado: impórtalo como nuevo, pruébalo, y solo entonces apunta el dominio/proxy a
   este workflow en vez del viejo).
5. Reconfigura en Evolution API la URL del webhook del agente para incluir
   `?secret=EL_VALOR_DE_WA_AGENT_WEBHOOK_SECRET`.
6. Ejecuta la migración manual de contraseñas descrita al final de
   `migration-security.sql` (léela antes de correr nada — es un paso manual, no un script
   automático).
7. Smoke test: login real, crear una cita desde el panel, crear una reserva desde
   `reservar.html`, y confirmar que un `curl` con un `org_id` ajeno y sin el JWT correcto
   recibe error en vez de datos.

## Qué NO cubre esto

- Rate limiting / bloqueo tras intentos fallidos de login — no está en este workflow.
- Firma HMAC del webhook de MercadoPago (`x-signature`) — hoy la seguridad de ese
  endpoint depende de la verificación contra la API de MP (`MP Get Payment`), que es la
  parte que de verdad importa (nunca confiar en el `status` del body), pero no valida la
  firma de la notificación en sí.
- El "premium black" (rediseño visual del frontend) — este directorio es solo el backend.
