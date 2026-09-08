# Workflow `agenda-auth` — login/registro con hash real + JWT

Reemplaza el Code Node actual (el que compara `password` en texto plano contra la tabla
`orgs`, si es así como está hoy) por estos dos nodos.

## Variables de entorno n8n requeridas
- `APP_JWT_SECRET` — 32+ bytes aleatorios (`openssl rand -hex 32`).
- `AUTIX_API_KEY` — la API key rotada (ver README).

## Nodo 1 — Code Node "Login/Registro" (Run Once for All Items)

```javascript
const bcrypt = require('bcryptjs'); // habilitar módulo en n8n (NODE_FUNCTION_ALLOW_EXTERNAL=bcryptjs)
const crypto = require('crypto');

const SECRET = $env.APP_JWT_SECRET;
const body = $input.first().json.body ?? $input.first().json;
const action = String(body.action || '').trim();

function signJWT(claims, ttlSeconds){
  const header = { alg: 'HS256', typ: 'JWT' };
  const payload = { ...claims, iat: Math.floor(Date.now()/1000), exp: Math.floor(Date.now()/1000) + ttlSeconds };
  const b64 = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
  const h = b64(header), p = b64(payload);
  const sig = crypto.createHmac('sha256', SECRET).update(`${h}.${p}`).digest('base64url');
  return `${h}.${p}.${sig}`;
}

// Rate limit simple: máx 5 intentos fallidos por org_id en 15 min.
// Requiere tabla auth_intentos(org_id TEXT, ts TIMESTAMPTZ DEFAULT now()).
// El nodo Postgres siguiente ("Check rate limit") hace:
//   SELECT count(*) FROM auth_intentos WHERE org_id = $1 AND ts > now() - interval '15 minutes'
// y este Code Node recibe ese count en item.json.intentos_recientes.

if (action === 'login') {
  const orgId = String(body.org_id || '').trim();
  const pass = String(body.password || '');
  if (!orgId || !pass) return [{ json: { ok: false, error: 'Completa los campos' } }];

  const intentos = Number($input.first().json.intentos_recientes ?? 0);
  if (intentos >= 5) {
    return [{ json: { ok: false, http: 429, code: 'RATE_LIMITED', error: 'Demasiados intentos. Espera 15 minutos.' } }];
  }

  // El siguiente nodo Postgres ("Get org by id") debe traer: id, nombre, slug, plan,
  // password_hash, trial_hasta, dias_restantes. Aquí asumimos que ya viene en el item
  // bajo la clave `org` (join hecho en el nodo Postgres anterior a este).
  const org = $input.first().json.org;
  if (!org || !bcrypt.compareSync(pass, org.password_hash)) {
    // Insertar registro en auth_intentos (nodo Postgres posterior) para contar este fallo
    return [{ json: { ok: false, error: 'Credenciales incorrectas', _log_intento_fallido: orgId } }];
  }

  if (org.trial_vencido) {
    return [{ json: { ok: false, trial_expired: true, org_id: org.id, nombre: org.nombre } }];
  }

  const token = signJWT({ sub: org.id, org_id: org.id, rol: org.rol || 'owner' }, 12 * 60 * 60); // 12h
  return [{ json: {
    ok: true, org_id: org.id, slug: org.slug, plan: org.plan, nombre: org.nombre,
    dias_restantes: org.dias_restantes, token
  } }];
}

if (action === 'register') {
  const slug = String(body.slug || '').trim();
  const pass = String(body.password || '');
  if (!/^[a-z0-9-]+$/.test(slug)) return [{ json: { ok: false, error: 'Slug inválido' } }];
  if (pass.length < 6) return [{ json: { ok: false, error: 'Contraseña muy corta' } }];

  const password_hash = bcrypt.hashSync(pass, 12);
  // El siguiente nodo Postgres inserta en orgs (org_id = slug o UUID nuevo) usando
  // password_hash como Query Parameter (nunca concatenado en el SQL).
  return [{ json: {
    ok: true,
    insert: {
      slug, password_hash,
      nombre: body.nombre, email: body.email, telefono: body.telefono,
      rubro: body.rubro, plan: 'trial'
    }
  } }];
}

return [{ json: { ok: false, code: 'BAD_ACTION', error: 'Acción no soportada' } }];
```

## Notas
- El frontend (`index.html`) ya guarda `d.token` en `SESSION_TOKEN` y lo manda como
  `Authorization: Bearer` en cada llamada — no requiere cambios adicionales una vez
  aplicado este nodo.
- `password_hash` en la tabla `usuarios`/`orgs` reemplaza cualquier columna `password`
  en texto plano. Si hoy existen contraseñas en texto plano, migrarlas con un script
  único que las re-hashee y luego eliminar la columna vieja.
