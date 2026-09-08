# Middleware de autorización — pegar como PRIMER Code Node en cada workflow de tenant

Aplica a: `agenda-clientes`, `agenda-reservas`, `agenda-movimientos`, `agenda-configuracion`
(acciones que no sean `getPublic`), `agenda-servicios`, `agenda-profesionales`,
`agenda-productos`, `agenda-dashboard`, `agenda-whatsapp`.

Esto es lo que cierra el hallazgo P0: **hoy cualquiera con el `org_id` público (el mismo
slug del link de reserva) puede leer/escribir los datos de ese negocio**, porque la única
credencial es la API key estática, igual para todos los tenants. Este nodo obliga a que
el `org_id` del body coincida con el `org_id` firmado dentro del JWT del usuario logueado.

```javascript
// n8n Code Node — "Auth Guard" (Run Once for All Items) — primer nodo del workflow
const crypto = require('crypto');
const SECRET = $env.APP_JWT_SECRET;

function verifyJWT(token) {
  const parts = String(token || '').split('.');
  if (parts.length !== 3) throw new Error('TOKEN_MALFORMADO');
  const [h, p, s] = parts;
  const expected = crypto.createHmac('sha256', SECRET).update(`${h}.${p}`).digest('base64url');
  const a = Buffer.from(s), b = Buffer.from(expected);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) throw new Error('FIRMA_INVALIDA');
  const claims = JSON.parse(Buffer.from(p, 'base64url').toString('utf8'));
  if (claims.exp * 1000 < Date.now()) throw new Error('TOKEN_EXPIRADO');
  return claims;
}

const item = $input.first().json;
const body = item.body ?? item;
const authHeader = item.headers?.authorization || item.headers?.Authorization || '';
const token = authHeader.replace(/^Bearer\s+/i, '');
const orgId = String(body.org_id || '').trim();

// El demo (org_id === 'demo') se maneja 100% en memoria en el frontend y nunca llega aquí.
if (!orgId) {
  return [{ json: { ok: false, http: 400, code: 'BAD_ORG', error: 'org_id requerido' } }];
}

try {
  const claims = verifyJWT(token);
  if (claims.org_id !== orgId) {
    // El token es válido pero es de OTRO negocio — este es el bug que existe hoy sin este nodo.
    return [{ json: { ok: false, http: 401, code: 'UNAUTHORIZED', error: 'Cross-tenant' } }];
  }
  return [{ json: { ...body, org_id: orgId, user_id: claims.sub, rol: claims.rol } }];
} catch (e) {
  return [{ json: { ok: false, http: 401, code: 'UNAUTHORIZED', error: e.message } }];
}
```

## Cómo conectarlo
1. Pega este Code Node justo después del Webhook Trigger, antes de cualquier nodo Postgres.
2. Añade un nodo **IF**: `{{$json.ok}}` es `false` → rama que devuelve la respuesta de error
   tal cual (con el `http` status code correcto vía el nodo "Respond to Webhook" configurado
   en `Response Code = {{$json.http}}`). Rama `true` → continúa al resto del workflow.
3. Todos los nodos Postgres siguientes deben usar `{{$json.org_id}}` (el que sale de este
   nodo, ya verificado) en el `WHERE org_id = $1`, nunca el `org_id` crudo del body original.
