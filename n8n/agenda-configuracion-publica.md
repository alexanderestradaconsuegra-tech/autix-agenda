# Acción `getPublic` en `agenda-configuracion`

`reservar.html` (público, sin login) necesita el nombre del negocio para el encabezado,
pero **nunca** debe poder pedir la configuración completa (que incluye `mp_token` y las
credenciales de Evolution API/WhatsApp). Esta acción NO pasa por el middleware de
`_shared-auth-middleware.md` (es intencionalmente pública), pero solo devuelve campos
no sensibles.

```javascript
// n8n Code Node — dentro de agenda-configuracion, ANTES del Auth Guard,
// como una rama IF separada: {{$json.body.action}} === 'getPublic'
const body = $input.first().json.body ?? $input.first().json;
const orgId = String(body.org_id || '').trim();
if (!orgId) return [{ json: { ok: false, error: 'org_id requerido' } }];

// Nodo Postgres siguiente: SELECT nombre, rubro FROM orgs WHERE id = $1 (parametrizado)
// pasa el resultado como item.json.org
return [{ json: { org_id: orgId, _query_org_publico: true } }];
```

```sql
-- Nodo Postgres "Get org público" — Query Parameters: [orgId]
SELECT nombre, rubro FROM orgs WHERE id = $1 LIMIT 1;
```

```javascript
// n8n Code Node — formatear respuesta final de esta rama
const org = $input.first().json[0] || {};
return [{ json: { ok: true, nombre: org.nombre || '', rubro: org.rubro || '' } }];
```

Nunca agregues `mp_token`, `evo_key`, `evo_url`, `password_hash` ni ningún otro secreto
a esta rama. Si en el futuro se necesita más data pública (ej. dirección, horario), se
agrega explícitamente campo por campo — nunca haciendo `SELECT *`.
