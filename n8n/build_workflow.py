import json

nodes = []
connections = {}

def N(**kw):
    nodes.append(kw)

def C(src, outputs):
    connections[src] = {"main": [[{"node": t, "type": "main", "index": i} for (t, i) in branch] for branch in outputs]}

CORS_OPTS = {
    "responseHeaders": {
        "entries": [
            {"name": "Access-Control-Allow-Origin", "value": "*"},
            {"name": "Access-Control-Allow-Headers", "value": "Content-Type, x-api-key, authorization"},
            {"name": "Access-Control-Allow-Methods", "value": "POST, OPTIONS, GET"},
        ]
    }
}

def webhook(name, path, node_id, pos, webhook_id):
    N(parameters={"httpMethod": "POST", "path": path, "responseMode": "responseNode", "options": CORS_OPTS},
      id=node_id, name=name, type="n8n-nodes-base.webhook", typeVersion=2.1, position=pos, webhookId=webhook_id)

def code(name, node_id, pos, js):
    N(parameters={"jsCode": js}, id=node_id, name=name, type="n8n-nodes-base.code", typeVersion=2, position=pos)

def pg(name, node_id, pos, query, cred_id="kFJ2nvRHWp7qruLF", cred_name="AgendaOS DB"):
    N(parameters={"operation": "executeQuery", "query": query, "options": {}},
      id=node_id, name=name, type="n8n-nodes-base.postgres", typeVersion=2.6, position=pos,
      credentials={"postgres": {"id": cred_id, "name": cred_name}})

def resp(name, node_id, pos, body):
    N(parameters={"respondWith": "json", "responseBody": body, "options": {}},
      id=node_id, name=name, type="n8n-nodes-base.respondToWebhook", typeVersion=1.5, position=pos)

def switch(name, node_id, pos, rules):
    values = []
    for i, (label, action) in enumerate(rules):
        values.append({
            "conditions": {
                "options": {"caseSensitive": True, "leftValue": "", "typeValidation": "strict", "version": 3},
                "conditions": [{
                    "leftValue": "={{ $json.action }}",
                    "rightValue": action,
                    "operator": {"type": "string", "operation": "equals"},
                    "id": f"{node_id}-{i}"
                }],
                "combinator": "and"
            },
            "renameOutput": True,
            "outputKey": label
        })
    N(parameters={"rules": {"values": values}, "options": {}}, id=node_id, name=name,
      type="n8n-nodes-base.switch", typeVersion=3.4, position=pos)

def httpreq(name, node_id, pos, url, headers, body_expr, method="POST"):
    N(parameters={
        "method": method, "url": url, "sendHeaders": True,
        "headerParameters": {"parameters": headers},
        "sendBody": True, "specifyBody": "json", "jsonBody": body_expr,
        "options": {"timeout": 15000}
    }, id=node_id, name=name, type="n8n-nodes-base.httpRequest", typeVersion=4.2, position=pos)

RESP_OK = "={{ JSON.stringify({ ok: true, data: $input.all().map(i => i.json) }) }}"

# ============================================================================
# JWT / auth helper source, inlined into every Code node that needs a tenant
# guard. Kept as a single string so every copy is byte-identical.
# ============================================================================
JWT_BLOCK = r"""const crypto = require('crypto');
const JWT_SECRET = $env.APP_JWT_SECRET;
function verifyJWT(token){
  const parts = String(token||'').split('.');
  if (parts.length !== 3) throw new Error('TOKEN_MALFORMADO');
  const [h,p,s] = parts;
  const expected = crypto.createHmac('sha256', JWT_SECRET).update(`${h}.${p}`).digest('base64url');
  const a = Buffer.from(s), b = Buffer.from(expected);
  if (a.length !== b.length || !crypto.timingSafeEqual(a,b)) throw new Error('FIRMA_INVALIDA');
  const claims = JSON.parse(Buffer.from(p,'base64url').toString('utf8'));
  if (claims.exp*1000 < Date.now()) throw new Error('TOKEN_EXPIRADO');
  return claims;
}
function sqlEsc(v, max){ return String(v==null?'':v).replace(/'/g,"''").slice(0, max||100); }
function guardTenant(headers, org_id){
  const authHeader = headers?.authorization || headers?.Authorization || '';
  let claims;
  try { claims = verifyJWT(authHeader.replace(/^Bearer\s+/i,'')); }
  catch(e){ throw new Error('Unauthorized: ' + e.message); }
  if (claims.org_id !== org_id) throw new Error('Unauthorized: cross-tenant');
  return claims;
}
"""

def api_key_check():
    return "const __key = $input.first().json.headers?.['x-api-key'];\nif (__key !== $env.AUTIX_API_KEY) throw new Error('Unauthorized');\n"

# ============================================================================
# AUTH — login/registro con bcrypt-equivalente nativo (crypto.scrypt) + JWT
# ============================================================================
webhook("WH Auth1", "agenda-auth", "7a44bd1e-dcbd-4560-89ab-7b0eb5389a61", [6112, 2032], "f425eb98-da55-4976-9131-2e5a6eaff8dc")

code("Extract Auth1", "4fda0aa0-779f-4997-9cdf-89d0b340919c", [6336, 2032], r"""%s
const b = $input.first().json.body || {};
const action = String(b.action || 'register').replace(/[^a-z]/gi, '').slice(0, 20);

const cleanText = (v, max = 100) => String(v || '').replace(/[<>"'&]/g, '').trim().slice(0, max);

function hashPassword(plain){
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(plain, salt, 64).toString('hex');
  return `${salt}:${hash}`;
}

if (action === 'login') {
  return [{ json: {
    action: 'login',
    org_id: String(b.org_id || '').toLowerCase().replace(/[^a-z0-9\-_]/gi, '').slice(0, 50),
    password: String(b.password || '').slice(0, 100)
  } }];
}

const rawNombre = cleanText(b.nombre || b.negocio, 100);
const rawSlug = String(b.slug || b.org_id || rawNombre).toLowerCase().normalize('NFD').replace(/[̀-ͯ]/g, '').replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 80);
const orgId = String(b.org_id || rawSlug).toLowerCase().replace(/[^a-z0-9\-_]/gi, '').slice(0, 50);

return [{ json: {
  action, org_id: orgId,
  password: String(b.password || '').slice(0, 100),
  password_hash: hashPassword(String(b.password || '')),
  nombre: rawNombre, slug: rawSlug || orgId,
  email: sqlEsc(String(b.email || '').trim().toLowerCase(), 100),
  telefono: String(b.telefono || b.whatsapp || '').replace(/[^0-9+\s]/g, '').slice(0, 20),
  contacto: sqlEsc(cleanText(b.contacto || b.nombre_contacto || rawNombre, 100)),
  rubro: sqlEsc(cleanText(b.rubro || 'Otro', 50)),
  origen: String(b.origen || 'landing').replace(/[^a-z0-9_\-]/gi, '').slice(0, 30)
} }];""" % (api_key_check() + JWT_BLOCK))

switch("SW Auth1", "c90f80a0-69b9-4497-909f-d9c9a0c9cfed", [6544, 2000], [("login", "login"), ("register", "register")])

pg("PG Login", "e6fcc040-62f8-4dd9-8fd5-05117b362dcf", [6784, 1808], r"""SELECT org_id, nombre, COALESCE(slug, org_id) AS slug, plan, activo, plan_activo, password_hash,
  trial_expira,
  ROUND(EXTRACT(EPOCH FROM (trial_expira - NOW()))/86400)::int AS dias_restantes
FROM public.negocios
WHERE org_id = '{{ $json.org_id.replace(/'/g, "''") }}'
  AND activo = true
LIMIT 1;""")

code("Auth Response1", "7e45db14-c916-48fa-9eb7-fa4bab0447fa", [7040, 1808], r"""const crypto = require('crypto');
const JWT_SECRET = $env.APP_JWT_SECRET;

function verifyPassword(plain, stored){
  if (!stored || !stored.includes(':')) return false;
  const [salt, hash] = stored.split(':');
  const hashBuf = Buffer.from(hash, 'hex');
  const testBuf = crypto.scryptSync(plain, salt, 64);
  return hashBuf.length === testBuf.length && crypto.timingSafeEqual(hashBuf, testBuf);
}
function signJWT(claims, ttlSeconds){
  const b64 = o => Buffer.from(JSON.stringify(o)).toString('base64url');
  const h = b64({alg:'HS256',typ:'JWT'});
  const p = b64({...claims, iat:Math.floor(Date.now()/1000), exp:Math.floor(Date.now()/1000)+ttlSeconds});
  const sig = crypto.createHmac('sha256', JWT_SECRET).update(`${h}.${p}`).digest('base64url');
  return `${h}.${p}.${sig}`;
}

const items = $input.all();
const plainPassword = $('Extract Auth1').first().json.password;

if (!items.length || !items[0].json.org_id) {
  return [{ json: { ok: false, error: 'Credenciales incorrectas' } }];
}
const n = items[0].json;

if (!verifyPassword(plainPassword, n.password_hash)) {
  return [{ json: { ok: false, error: 'Credenciales incorrectas' } }];
}

const planActivo = n.plan_activo || 'trial';
const diasRestantes = parseInt(n.dias_restantes || 0);
if (planActivo === 'trial' && diasRestantes < 0) {
  return [{ json: { ok: false, trial_expired: true, error: 'Tu período de prueba ha terminado', org_id: n.org_id, nombre: n.nombre } }];
}

const token = signJWT({ sub: n.org_id, org_id: n.org_id, rol: 'owner' }, 12 * 60 * 60);
return [{ json: { ok: true, org_id: n.org_id, nombre: n.nombre, slug: n.slug || n.org_id, plan: planActivo, dias_restantes: diasRestantes, token } }];""")

resp("Resp Auth1", "c1555ebf-ef3d-4565-b465-e4d3a5d82aea", [7312, 1808], "={{ JSON.stringify($json) }}")

pg("PG Auth Check Existing", "e22c2a9f-f72b-4337-b9a8-bca1b2978203", [6768, 2112], r"""SELECT
  '{{ $json.org_id }}'::text AS org_id,
  '{{ $json.nombre }}'::text AS nombre,
  '{{ $json.slug }}'::text AS slug,
  '{{ $json.email }}'::text AS email,
  '{{ $json.telefono }}'::text AS telefono,
  '{{ $json.contacto }}'::text AS contacto,
  '{{ $json.rubro }}'::text AS rubro,
  '{{ $json.origen }}'::text AS origen,
  '{{ $json.password_hash }}'::text AS password_hash,
  COUNT(*)::int AS exists_count
FROM public.negocios
WHERE org_id = '{{ $json.org_id }}'
   OR email = '{{ $json.email }}'
   OR slug = '{{ $json.slug }}';""")

N(parameters={
    "conditions": {
        "options": {"caseSensitive": True, "leftValue": "", "typeValidation": "strict", "version": 2},
        "conditions": [{
            "id": "f8c969f4-c2b0-41cd-b174-c5afd8cd332b",
            "leftValue": "={{ $json.exists_count }}",
            "rightValue": 0,
            "operator": {"type": "number", "operation": "larger"}
        }],
        "combinator": "and"
    },
    "options": {}
}, id="e1533842-3aae-43b5-a821-d0e5c904e596", name="IF Auth Existing", type="n8n-nodes-base.if", typeVersion=2.2, position=[6992, 2112])

code("Register Duplicate Response", "f5db06d8-10b8-4e6d-ba8e-9b864b90f297", [7216, 2032],
     "return [{ json: { ok: false, error: 'Este negocio, slug o correo ya está registrado', code: 'ORG_SLUG_OR_EMAIL_EXISTS' } }];")

pg("PG Register", "18e05478-9b99-423f-a904-11985dba9706", [7216, 2208], r"""INSERT INTO negocios (
  org_id, password_hash, nombre, slug, plan, activo, trial_start,
  trial_expira, plan_activo,
  email, telefono, contacto, rubro
) VALUES (
  '{{ $json.org_id }}',
  '{{ $json.password_hash }}',
  '{{ $json.nombre }}',
  '{{ $json.slug }}',
  'trial',
  true,
  NOW(),
  NOW() + INTERVAL '7 days',
  'trial',
  '{{ $json.email }}',
  '{{ $json.telefono }}',
  '{{ $json.contacto }}',
  '{{ $json.rubro }}'
)
ON CONFLICT (org_id) DO UPDATE SET
  nombre = EXCLUDED.nombre,
  email = EXCLUDED.email,
  telefono = EXCLUDED.telefono,
  contacto = EXCLUDED.contacto,
  rubro = EXCLUDED.rubro
RETURNING
  org_id, nombre, slug, plan, email, telefono, contacto, rubro,
  trial_expira::text AS trial_end,
  plan_activo""")

pg("PG Register Create Config", "998fab22-29a8-4775-8814-33514c76ab18", [7424, 2208], r"""INSERT INTO public.configuracion (org_id, datos, updated_at)
VALUES (
  '{{ $json.org_id }}',
  '{"tema":"blue","moneda":"CLP","timezone":"America/Santiago","whatsapp":"","landing_activa":true,"trial":true}'::jsonb,
  NOW()
)
ON CONFLICT (org_id) DO UPDATE SET datos = EXCLUDED.datos, updated_at = NOW()
RETURNING
  '{{ $json.org_id }}'::text AS org_id, '{{ $json.nombre }}'::text AS nombre,
  '{{ $json.slug }}'::text AS slug, '{{ $json.plan }}'::text AS plan,
  '{{ $json.email }}'::text AS email,
  '{{ $json.telefono }}'::text AS telefono, '{{ $json.contacto }}'::text AS contacto,
  '{{ $json.rubro }}'::text AS rubro, '{{ $json.trial_end }}'::text AS trial_end;""")

pg("PG Register Seed Servicio", "99f1519e-ba2a-4fc1-bf6f-e1648ddb78ad", [7648, 2208], r"""INSERT INTO public.servicios (org_id, nombre, descripcion, duracion_min, precio, requiere_pago)
VALUES ('{{ $json.org_id }}', 'Servicio inicial', 'Servicio de ejemplo para comenzar a usar AgendaOS', 60, 25000, false)
RETURNING '{{ $json.org_id }}'::text AS org_id, '{{ $json.nombre }}'::text AS nombre, '{{ $json.slug }}'::text AS slug, '{{ $json.plan }}'::text AS plan, '{{ $json.email }}'::text AS email, '{{ $json.telefono }}'::text AS telefono, '{{ $json.contacto }}'::text AS contacto, '{{ $json.rubro }}'::text AS rubro, '{{ $json.trial_end }}'::text AS trial_end;""")

pg("PG Register Seed Profesional", "72a88037-01d6-4c6b-a0f6-63299191726d", [7872, 2208], r"""INSERT INTO public.profesionales (org_id, nombre, telefono, email, comision_pct)
VALUES ('{{ $json.org_id }}', COALESCE(NULLIF('{{ $json.contacto }}',''), '{{ $json.nombre }}'), '{{ $json.telefono }}', '{{ $json.email }}', 15)
RETURNING '{{ $json.org_id }}'::text AS org_id, '{{ $json.nombre }}'::text AS nombre, '{{ $json.slug }}'::text AS slug, '{{ $json.plan }}'::text AS plan, '{{ $json.email }}'::text AS email, '{{ $json.telefono }}'::text AS telefono, '{{ $json.contacto }}'::text AS contacto, '{{ $json.rubro }}'::text AS rubro, '{{ $json.trial_end }}'::text AS trial_end;""")

N(parameters={
    "fromEmail": "info@autix.pro", "toEmail": "={{ $json.email }}", "subject": "Bienvenido a AgendaOS 🚀",
    "html": "=<h2>Tu cuenta AgendaOS fue creada correctamente</h2><p>Tu negocio <b>{{ $json.nombre }}</b> ya tiene acceso al trial gratuito de 7 días.</p><ul><li><b>Usuario:</b> {{ $json.org_id }}</li><li><b>Plan:</b> Trial 7 días</li><li><b>Acceso:</b> <a href='https://app.agendaos.pro'>https://app.agendaos.pro</a></li></ul><p>Al finalizar el trial puedes activar tu plan Pro desde AgendaOS.</p>",
    "options": {}
}, id="12a0fd88-c331-445e-99fb-810909d7b3f8", name="Email Welcome Trial", type="n8n-nodes-base.emailSend",
   typeVersion=2.1, position=[8096, 2208], webhookId="c0c7b8c9-d188-4d45-b47f-ebf524ad9088",
   credentials={"smtp": {"id": "yg5JS5bayhagsQSE", "name": "SMTP account"}})

code("Register Success Response", "79620be3-495d-4ffb-9d5b-befc7bfe0a2f", [8336, 2208],
     "const n = $input.first().json;\nreturn [{ json: { ok: true, message: 'Cuenta creada correctamente', org_id: n.org_id, nombre: n.nombre, slug: n.slug, plan: n.plan || 'trial', status: 'active_trial', trial_end: n.trial_end, redirect: 'https://app.agendaos.pro' } }];")

resp("Resp Register1", "c88d35da-a93f-4fd7-83c4-5ae07f28a45e", [8544, 2032], "={{ JSON.stringify($json) }}")

C("WH Auth1", [[("Extract Auth1", 0)]])
C("Extract Auth1", [[("SW Auth1", 0)]])
C("SW Auth1", [[("PG Login", 0)], [("PG Auth Check Existing", 0)]])
C("PG Login", [[("Auth Response1", 0)]])
C("Auth Response1", [[("Resp Auth1", 0)]])
C("PG Auth Check Existing", [[("IF Auth Existing", 0)]])
C("IF Auth Existing", [[("Register Duplicate Response", 0)], [("PG Register", 0)]])
C("Register Duplicate Response", [[("Resp Register1", 0)]])
C("PG Register", [[("PG Register Create Config", 0)]])
C("PG Register Create Config", [[("PG Register Seed Servicio", 0)]])
C("PG Register Seed Servicio", [[("PG Register Seed Profesional", 0)]])
C("PG Register Seed Profesional", [[("Register Success Response", 0)]])
C("Register Success Response", [[("Resp Register1", 0)]])

print("auth section ok:", len(nodes), "nodes")

# ============================================================================
# RESERVAS
# ============================================================================
webhook("WH Reservas1", "agenda-reservas", "b979dd60-a6da-48a7-84e6-0fa724d43352", [10432, 2848], "edfe46a6-e9be-4f6a-ac14-1b6b6bbc145a")

code("Extract Reservas1", "d61f817b-220f-4acc-8b27-7a86fde19127", [10672, 2848], r"""%s%s
const b = $input.first().json.body;
const d = b.data || b;
const org_id = String(b.org_id || '').replace(/[^a-z0-9\-_]/gi,'').slice(0,50);
const __headers = $input.first().json.headers;
const __internalKey = __headers?.['x-internal-key'];
if (__internalKey && __internalKey === $env.N8N_INTERNAL_KEY) {
  // Llamada server-to-server desde "Validar y preparar reserva" (reserva pública) —
  // ya validó los campos, org_id aquí solo decide en qué negocio se crea la cita,
  // exactamente lo que una reserva pública debe poder hacer.
} else {
  guardTenant(__headers, org_id);
}

return [{ json: {
  action: String(b.action || '').replace(/[^a-z0-9_]/gi,'').slice(0,30),
  org_id,
  id: d.id || null,
  cliente_nombre: sqlEsc(String(d.cliente_nombre || '').replace(/[<>"&]/g,''), 100),
  cliente_tel: String(d.cliente_tel || '').replace(/[^0-9+\s]/g,'').slice(0,20),
  cliente_email: sqlEsc(d.cliente_email, 100),
  servicio_id: parseInt(d.servicio_id || 0),
  servicio_nombre: sqlEsc(String(d.servicio_nombre || '').replace(/[<>"&]/g,''), 100),
  profesional_id: parseInt(d.profesional_id || 0),
  profesional_nombre: sqlEsc(String(d.profesional_nombre || '').replace(/[<>"&]/g,''), 100),
  fecha_inicio: sqlEsc(d.fecha_inicio, 30),
  fecha_fin: sqlEsc(d.fecha_fin, 30),
  monto: parseFloat(d.monto || 0),
  estado: String(d.estado || b.estado || 'confirmada').replace(/[^a-z]/g,'').slice(0,20),
  origen: String(d.origen || 'admin').replace(/[^a-z]/g,'').slice(0,20),
  notas: sqlEsc(String(d.notas || '').replace(/[<>"&]/g,''), 300),
  fecha: String(b.fecha || '').slice(0,10),
} }];""" % (api_key_check(), JWT_BLOCK))

switch("SW Reservas1", "98e41aa5-6572-4886-baae-34466c000b49", [10896, 2800],
       [("getAll", "getAll"), ("save", "save"), ("delete", "delete"), ("getByFecha", "getByFecha"), ("updateEstado", "updateEstado")])

resp("Resp Reservas1", "a6301809-d327-4fda-80a0-5c3b45ba4bbd", [12160, 2944], RESP_OK)

pg("PG Reservas GetAll", "637fa053-f545-413d-98d0-07d84f965cdd", [11120, 2544], r"""SELECT
  r.id, r.org_id, r.cliente_nombre, r.cliente_tel, r.cliente_email,
  r.servicio_id, r.servicio_nombre, r.profesional_id, r.profesional_nombre,
  r.fecha_inicio::text, r.fecha_fin::text, r.estado, r.monto, r.origen, r.notas,
  r.created_at::text
FROM reservas r
WHERE r.org_id = '{{ $json.org_id }}'
ORDER BY r.fecha_inicio DESC
LIMIT 500""")

pg("PG Reservas Save", "d75cdb73-6ab0-42d3-a9f5-5603ed941106", [11120, 2688], r"""WITH conflict_check AS (
  SELECT COUNT(*) AS cnt
  FROM reservas
  WHERE org_id = '{{ $json.org_id }}'
    AND estado != 'cancelada'
    AND (
      (CASE WHEN '{{ $json.profesional_id }}' != '0' THEN profesional_id = {{ $json.profesional_id }} ELSE true END)
    )
    AND tstzrange(fecha_inicio::timestamptz, fecha_fin::timestamptz, '[)') &&
        tstzrange('{{ $json.fecha_inicio }}'::timestamptz, '{{ $json.fecha_fin }}'::timestamptz, '[)')
)
INSERT INTO reservas (
  org_id, cliente_nombre, cliente_tel, cliente_email,
  servicio_id, servicio_nombre, profesional_id, profesional_nombre,
  fecha_inicio, fecha_fin, estado, monto, origen, notas
)
SELECT
  '{{ $json.org_id }}','{{ $json.cliente_nombre }}','{{ $json.cliente_tel }}','{{ $json.cliente_email }}',
  {{ $json.servicio_id }},'{{ $json.servicio_nombre }}',{{ $json.profesional_id }},'{{ $json.profesional_nombre }}',
  '{{ $json.fecha_inicio }}'::TIMESTAMPTZ,'{{ $json.fecha_fin }}'::TIMESTAMPTZ,
  '{{ $json.estado }}',{{ $json.monto }},'{{ $json.origen }}','{{ $json.notas }}'
WHERE (SELECT cnt FROM conflict_check) = 0
RETURNING *, (SELECT cnt FROM conflict_check) AS conflict_count""")

code("Check Conflict Result", "fb16ffca-807e-4fc6-9dc7-3a719913f91e", [11792, 2656], r"""const items = $input.all();
if (!items.length || !items[0].json || !items[0].json.id) {
  return [{ json: { ok: false, conflict: true, error: 'Ese horario ya está reservado. Por favor elige otro.' } }];
}
const r = items[0].json;
return [{ json: { ok: true, id: r.id, estado: r.estado, fecha_inicio: r.fecha_inicio, cliente_nombre: r.cliente_nombre } }];""")

pg("PG Reservas Delete", "31cfed33-1aeb-4cea-bdda-a5a83a7827d4", [11120, 2848], "DELETE FROM reservas WHERE id = {{ $json.id }} AND org_id = '{{ $json.org_id }}' RETURNING id")

pg("PG Reservas ByFecha1", "a4cc5d73-7372-4139-9ad4-b3190b2f31d3", [11120, 3008], "SELECT * FROM reservas WHERE org_id = '{{ $json.org_id }}' AND DATE(fecha_inicio) = '{{ $json.fecha }}'::DATE ORDER BY fecha_inicio")

pg("PG Reservas Update1", "ce1e3cdf-3801-4d86-8c6a-058514038f75", [11136, 3152], "UPDATE reservas SET estado = '{{ $json.estado }}', updated_at = NOW() WHERE id = {{ $json.id }} AND org_id = '{{ $json.org_id }}' RETURNING *")

C("WH Reservas1", [[("Extract Reservas1", 0)]])
C("Extract Reservas1", [[("SW Reservas1", 0)]])
C("SW Reservas1", [[("PG Reservas GetAll", 0)], [("PG Reservas Save", 0)], [("PG Reservas Delete", 0)], [("PG Reservas ByFecha1", 0)], [("PG Reservas Update1", 0)]])
C("PG Reservas GetAll", [[("Resp Reservas1", 0)]])
C("PG Reservas Save", [[("Check Conflict Result", 0)]])
C("Check Conflict Result", [[("Resp Reservas1", 0)]])
C("PG Reservas Delete", [[("Resp Reservas1", 0)]])
C("PG Reservas ByFecha1", [[("Resp Reservas1", 0)]])
C("PG Reservas Update1", [[("Resp Reservas1", 0)]])

print("reservas section ok:", len(nodes), "nodes")

# ============================================================================
# CLIENTES
# ============================================================================
webhook("WH Clientes1", "agenda-clientes", "8d269774-c4f0-4f97-ba8c-6a367734d8e3", [6848, 2800], "8013e94b-f411-43f9-9189-9361cae9e517")

code("Extract Clientes1", "05cf0153-6591-4dd9-a182-819a39d89d7f", [7088, 2800], r"""%s%s
const b = $input.first().json.body;
const d = b.data || b;
const org_id = String(b.org_id || '').replace(/[^a-z0-9\-_]/gi,'').slice(0,50);
guardTenant($input.first().json.headers, org_id);

return [{ json: {
  action: String(b.action || '').replace(/[^a-z0-9_]/gi,'').slice(0,30),
  org_id,
  id: d.id || null,
  nombre: sqlEsc(String(d.nombre || '').replace(/[<>"&]/g,''), 100),
  telefono: String(d.telefono || '').replace(/[^0-9+\s]/g,'').slice(0,20),
  email: sqlEsc(d.email, 100),
  notas: sqlEsc(String(d.notas || '').replace(/[<>"&]/g,''), 300),
} }];""" % (api_key_check(), JWT_BLOCK))

switch("SW Clientes1", "9b952fa0-0036-4034-a478-c277e6701445", [7312, 2768],
       [("getAll", "getAll"), ("save", "save"), ("delete", "delete"), ("update", "update")])

resp("Resp Clientes1", "2f9b67b6-95b5-49c3-a865-6955b5f6af7d", [7872, 2848], RESP_OK)

pg("PG Clientes GetAll1", "f214af7d-20a3-453c-95c0-157f6a62685b", [7584, 2624], r"""SELECT c.*, COUNT(r.id) as total_citas, COALESCE(SUM(r.monto) FILTER (WHERE r.estado='completada'),0) as gasto_total, MAX(r.fecha_inicio) FILTER (WHERE r.estado='completada') as ultima_visita FROM clientes c LEFT JOIN reservas r ON r.cliente_tel = c.telefono AND r.org_id = c.org_id WHERE c.org_id = '{{ $json.org_id }}' GROUP BY c.id ORDER BY c.nombre""")

pg("PG Clientes Save1", "af3b20f5-b713-4561-aa30-9eafcb4fddf9", [7584, 2784], r"""INSERT INTO clientes (org_id, nombre, telefono, email, notas)
VALUES ('{{ $json.org_id }}','{{ $json.nombre }}','{{ $json.telefono }}','{{ $json.email }}','{{ $json.notas }}')
ON CONFLICT (org_id, telefono) DO UPDATE
SET nombre = EXCLUDED.nombre,
    email = COALESCE(NULLIF(EXCLUDED.email,''), clientes.email),
    notas = COALESCE(NULLIF(EXCLUDED.notas,''), clientes.notas),
    updated_at = NOW()
RETURNING *""")

pg("PG Clientes Delete1", "a200d7b2-bdc4-44f5-a086-cb053f11d893", [7584, 2944], "DELETE FROM clientes WHERE id = {{ $json.id }} AND org_id = '{{ $json.org_id }}' RETURNING id")

pg("PG Clientes Update", "92b4d31b-2479-473c-9490-6529e86576fb", [7584, 3104], r"""UPDATE clientes
SET nombre='{{ $json.nombre }}', telefono='{{ $json.telefono }}',
    email='{{ $json.email }}', notas='{{ $json.notas }}', updated_at=NOW()
WHERE id={{ $json.id }} AND org_id='{{ $json.org_id }}'
RETURNING *""")

C("WH Clientes1", [[("Extract Clientes1", 0)]])
C("Extract Clientes1", [[("SW Clientes1", 0)]])
C("SW Clientes1", [[("PG Clientes GetAll1", 0)], [("PG Clientes Save1", 0)], [("PG Clientes Delete1", 0)], [("PG Clientes Update", 0)]])
C("PG Clientes GetAll1", [[("Resp Clientes1", 0)]])
C("PG Clientes Save1", [[("Resp Clientes1", 0)]])
C("PG Clientes Delete1", [[("Resp Clientes1", 0)]])
C("PG Clientes Update", [[("Resp Clientes1", 0)]])

print("clientes section ok:", len(nodes), "nodes")

# ============================================================================
# SERVICIOS
# ============================================================================
webhook("WH Servicios1", "agenda-servicios", "09ad2add-6695-4146-ad0d-e00e63a2ded4", [8592, 2944], "706f239d-25f1-4246-a7f2-41b588086ac2")

code("Extract Servicios1", "c8ab2b04-a60f-4883-8948-307ef2446105", [8832, 2944], r"""%s%s
const b = $input.first().json.body;
const d = b.data || b;
const org_id = String(b.org_id || '').replace(/[^a-z0-9\-_]/gi,'').slice(0,50);
const action = String(b.action || '').replace(/[^a-z0-9_]/gi,'').slice(0,30);

// getAll es lo que usa reservar.html (público, sin login) además del panel — no exige guard
if (action !== 'getAll') guardTenant($input.first().json.headers, org_id);

return [{ json: {
  action, org_id,
  id: d.id || null,
  nombre: sqlEsc(String(d.nombre || '').replace(/[<>"&]/g,''), 100),
  descripcion: sqlEsc(String(d.descripcion || '').replace(/[<>"&]/g,''), 300),
  duracion_min: parseInt(d.duracion_min || 60),
  precio: parseFloat(d.precio || 0),
  requiere_pago: d.requiere_pago === true || d.requiere_pago === 'true',
  foto_url: String(d.foto_url || '').slice(0,500000)
} }];""" % (api_key_check(), JWT_BLOCK))

switch("SW Servicios1", "abf9e0aa-0fb7-4ab6-ae3e-ee9b12c5fc38", [9040, 2896],
       [("getAll", "getAll"), ("save", "save"), ("delete", "delete"), ("toggle", "toggle"), ("update", "update")])

resp("Resp Servicios1", "1ea46f13-c7c3-4be7-a230-f850c8ba1264", [9776, 2912], RESP_OK)

pg("PG Servicios GetAll1", "a7c31758-1ed0-487f-87db-8536796cd192", [9392, 2688], "SELECT * FROM servicios WHERE org_id = '{{ $json.org_id }}' ORDER BY nombre")

pg("PG Servicios Save1", "ff1d34f6-9709-4129-9a81-a13d7bfffa65", [9392, 2848], r"""INSERT INTO servicios (org_id, nombre, descripcion, duracion_min, precio, requiere_pago, foto_url)
VALUES ('{{ $json.org_id }}','{{ $json.nombre }}','{{ $json.descripcion }}',{{ $json.duracion_min }},{{ $json.precio }},{{ $json.requiere_pago }},'{{ $json.foto_url }}')
RETURNING *""")

pg("PG Servicios Delete1", "83804013-db40-4bcd-9071-d5df41e5619b", [9392, 2992], "DELETE FROM servicios WHERE id = {{ $json.id }} AND org_id = '{{ $json.org_id }}' RETURNING id")

pg("PG Svc Toggle", "7b7380cd-748b-416e-974c-b4ff7a87e8bc", [9392, 3120], "UPDATE servicios SET activo = NOT activo, updated_at = NOW() WHERE id = {{ $json.id }} AND org_id = '{{ $json.org_id }}' RETURNING id, activo")

pg("PG Servicios Update", "1bca0298-e9d0-4b75-9d4f-a8e242fa95cf", [9392, 3248], r"""UPDATE servicios
SET nombre='{{ $json.nombre }}', descripcion='{{ $json.descripcion }}',
    duracion_min={{ $json.duracion_min }}, precio={{ $json.precio }},
    requiere_pago={{ $json.requiere_pago }}, updated_at=NOW()
WHERE id={{ $json.id }} AND org_id='{{ $json.org_id }}'
RETURNING *""")

C("WH Servicios1", [[("Extract Servicios1", 0)]])
C("Extract Servicios1", [[("SW Servicios1", 0)]])
C("SW Servicios1", [[("PG Servicios GetAll1", 0)], [("PG Servicios Save1", 0)], [("PG Servicios Delete1", 0)], [("PG Svc Toggle", 0)], [("PG Servicios Update", 0)]])
C("PG Servicios GetAll1", [[("Resp Servicios1", 0)]])
C("PG Servicios Save1", [[("Resp Servicios1", 0)]])
C("PG Servicios Delete1", [[("Resp Servicios1", 0)]])
C("PG Svc Toggle", [[("Resp Servicios1", 0)]])
C("PG Servicios Update", [[("Resp Servicios1", 0)]])

print("servicios section ok:", len(nodes), "nodes")

# ============================================================================
# PROFESIONALES
# ============================================================================
webhook("WH Profesionales1", "agenda-profesionales", "d41c5b95-8ab1-489a-bef1-32833581536e", [7280, 3504], "c5601e5f-5d68-41a7-8708-9588983c80c1")

code("Extract Profesionales1", "931b31a0-5fb9-4c66-8b40-9585a0a3a23a", [7520, 3504], r"""%s%s
const b = $input.first().json.body;
const d = b.data || b;
const org_id = String(b.org_id || '').replace(/[^a-z0-9\-_]/gi,'').slice(0,50);
const action = String(b.action || '').replace(/[^a-z0-9_]/gi,'').slice(0,30);
if (action !== 'getAll') guardTenant($input.first().json.headers, org_id);

return [{ json: {
  action, org_id,
  id: d.id || null,
  nombre: sqlEsc(String(d.nombre || '').replace(/[<>"&]/g,''), 100),
  telefono: String(d.telefono || '').replace(/[^0-9+\s]/g,'').slice(0,20),
  email: sqlEsc(d.email, 100),
  comision_pct: parseFloat(d.comision_pct || 15),
  foto_url: String(d.foto_url || '').slice(0,500000)
} }];""" % (api_key_check(), JWT_BLOCK))

switch("SW Profesionales1", "71a98ff7-73f6-45c5-a4e3-ce245388089d", [7776, 3472],
       [("getAll", "getAll"), ("save", "save"), ("delete", "delete"), ("update", "update")])

resp("Resp Profesionales1", "2b35a2ec-94d8-400b-9eaf-2374db8e95bd", [8544, 3472], RESP_OK)

pg("PG Profesionales GetAll1", "349a63e9-e55b-4aaa-9973-2839d43b1e9b", [8192, 3200], r"""SELECT p.*, COUNT(r.id) FILTER (WHERE DATE_TRUNC('month',r.fecha_inicio)=DATE_TRUNC('month',NOW()) AND r.estado!='cancelada') as citas_mes FROM profesionales p LEFT JOIN reservas r ON p.id=r.profesional_id AND p.org_id=r.org_id WHERE p.org_id='{{ $json.org_id }}' GROUP BY p.id ORDER BY p.nombre""")

pg("PG Profesionales Save1", "b4f5f9d5-3ab3-4bf3-ba8e-159abbe30bf8", [8192, 3376], r"""INSERT INTO profesionales (org_id, nombre, telefono, email, comision_pct, foto_url)
VALUES ('{{ $json.org_id }}','{{ $json.nombre }}','{{ $json.telefono }}','{{ $json.email }}',{{ $json.comision_pct }},'{{ $json.foto_url }}')
RETURNING *""")

pg("PG Profesionales Delete1", "c705e2c3-0245-4dce-a4ce-f3d6c92a8ea9", [8192, 3552], "DELETE FROM profesionales WHERE id = {{ $json.id }} AND org_id = '{{ $json.org_id }}' RETURNING id")

pg("PG Profesionales Update", "96e223b5-8c0d-45e5-80e8-b77224c6f253", [8192, 3760], r"""UPDATE profesionales
SET nombre='{{ $json.nombre }}', telefono='{{ $json.telefono }}',
    email='{{ $json.email }}', comision_pct={{ $json.comision_pct }}, updated_at=NOW()
WHERE id={{ $json.id }} AND org_id='{{ $json.org_id }}'
RETURNING *""")

C("WH Profesionales1", [[("Extract Profesionales1", 0)]])
C("Extract Profesionales1", [[("SW Profesionales1", 0)]])
C("SW Profesionales1", [[("PG Profesionales GetAll1", 0)], [("PG Profesionales Save1", 0)], [("PG Profesionales Delete1", 0)], [("PG Profesionales Update", 0)]])
C("PG Profesionales GetAll1", [[("Resp Profesionales1", 0)]])
C("PG Profesionales Save1", [[("Resp Profesionales1", 0)]])
C("PG Profesionales Delete1", [[("Resp Profesionales1", 0)]])
C("PG Profesionales Update", [[("Resp Profesionales1", 0)]])

print("profesionales section ok:", len(nodes), "nodes")

# ============================================================================
# PRODUCTOS
# ============================================================================
webhook("WH Productos1", "agenda-productos", "11bb7dad-353e-4270-9e5a-dccf16df0a8a", [8784, 3696], "16eeda47-ad01-4246-b31e-7429a8aa9c27")

code("Extract Productos1", "6e977da4-434d-4bee-ab8a-dfe3af6cac5c", [8992, 3696], r"""%s%s
const b = $input.first().json.body;
const d = b.data || b;
const org_id = String(b.org_id || '').replace(/[^a-z0-9\-_]/gi,'').slice(0,50);
guardTenant($input.first().json.headers, org_id);

return [{ json: {
  action: String(b.action || '').replace(/[^a-z0-9_]/gi,'').slice(0,30),
  org_id,
  id: d.id || null,
  nombre: sqlEsc(String(d.nombre || '').replace(/[<>"&]/g,''), 100),
  categoria: sqlEsc(String(d.categoria || 'General').replace(/[<>"&]/g,''), 50),
  precio_compra: parseFloat(d.precio_compra || 0),
  precio_venta: parseFloat(d.precio_venta || 0),
  stock: parseInt(d.stock || 0),
  foto_url: String(d.foto_url || '').slice(0,500000)
} }];""" % (api_key_check(), JWT_BLOCK))

switch("SW Productos1", "a68e8dd9-085b-4b45-bd8f-eefb5d35b818", [9184, 3664],
       [("getAll", "getAll"), ("save", "save"), ("delete", "delete"), ("toggle", "toggle"), ("update", "update")])

resp("Resp Productos1", "bc125088-7708-4874-bd2b-0f35814999bf", [9760, 3696], RESP_OK)

pg("PG Productos GetAll1", "37961392-2cf8-4f7f-9abb-64a83405d09c", [9472, 3488], "SELECT * FROM productos WHERE org_id = '{{ $json.org_id }}' ORDER BY categoria, nombre")

pg("PG Productos Save1", "4b0f033c-47b7-4f84-9e20-58393bf5b9c5", [9472, 3696], r"""INSERT INTO productos (org_id, nombre, categoria, precio_compra, precio_venta, stock, foto_url)
VALUES ('{{ $json.org_id }}','{{ $json.nombre }}','{{ $json.categoria }}',{{ $json.precio_compra }},{{ $json.precio_venta }},{{ $json.stock }},'{{ $json.foto_url }}')
RETURNING *""")

pg("PG Productos Delete1", "89535640-e531-401c-bb5c-05390c0d3200", [9472, 3872], "DELETE FROM productos WHERE id = {{ $json.id }} AND org_id = '{{ $json.org_id }}' RETURNING id")

pg("PG Prod Toggle1", "77c9e0ab-1c32-4172-a0f9-3251867d4367", [9488, 4080], "UPDATE productos SET activo = NOT activo, updated_at = NOW() WHERE id = {{ $json.id }} AND org_id = '{{ $json.org_id }}' RETURNING id, activo")

pg("PG Productos Update", "b1f39a90-1a1a-4b1a-9a1a-1a1a1a1a1a1a", [9472, 3984], r"""UPDATE productos
SET nombre='{{ $json.nombre }}', categoria='{{ $json.categoria }}',
    precio_compra={{ $json.precio_compra }}, precio_venta={{ $json.precio_venta }},
    stock={{ $json.stock }}, foto_url='{{ $json.foto_url }}', updated_at=NOW()
WHERE id={{ $json.id }} AND org_id='{{ $json.org_id }}'
RETURNING *""")

C("WH Productos1", [[("Extract Productos1", 0)]])
C("Extract Productos1", [[("SW Productos1", 0)]])
C("SW Productos1", [[("PG Productos GetAll1", 0)], [("PG Productos Save1", 0)], [("PG Productos Delete1", 0)], [("PG Prod Toggle1", 0)], [("PG Productos Update", 0)]])
C("PG Productos GetAll1", [[("Resp Productos1", 0)]])
C("PG Productos Save1", [[("Resp Productos1", 0)]])
C("PG Productos Delete1", [[("Resp Productos1", 0)]])
C("PG Prod Toggle1", [[("Resp Productos1", 0)]])
C("PG Productos Update", [[("Resp Productos1", 0)]])

print("productos section ok:", len(nodes), "nodes")

# ============================================================================
# MOVIMIENTOS
# ============================================================================
webhook("WH Movimientos1", "agenda-movimientos", "5a46c3f9-b9c9-455e-b3ad-80db790caf47", [7280, 4144], "aa88b995-343a-4ba0-b73f-416bd7999461")

code("Extract Movimientos1", "168a84d5-bc5d-4dc4-b812-fc39a7cf3c7d", [7472, 4144], r"""%s%s
const b = $input.first().json.body;
const d = b.data || b;
const org_id = String(b.org_id || '').replace(/[^a-z0-9\-_]/gi,'').slice(0,50);
guardTenant($input.first().json.headers, org_id);

return [{ json: {
  action: String(b.action || '').replace(/[^a-z0-9_]/gi,'').slice(0,30),
  org_id,
  id: d.id || null,
  tipo: String(d.tipo || 'eg').replace(/[^a-z]/g,'').slice(0,5),
  descripcion: sqlEsc(String(d.descripcion || '').replace(/[<>"&]/g,''), 200),
  monto: parseFloat(d.monto || 0),
  fecha: String(d.fecha || '').slice(0,10) || new Date().toISOString().split('T')[0],
} }];""" % (api_key_check(), JWT_BLOCK))

switch("SW Movimientos1", "b066d905-cc5b-4993-8c88-0330890daa3e", [7664, 4128],
       [("getAll", "getAll"), ("save", "save"), ("delete", "delete")])

resp("Resp Movimientos1", "fe967adb-e5f1-4373-8524-99fe1a3581f2", [8352, 4144], RESP_OK)

pg("PG Movimientos GetAll1", "53c6fa07-ce0a-4a1f-9051-ab8276b180a4", [8000, 3984], "SELECT * FROM movimientos WHERE org_id = '{{ $json.org_id }}' ORDER BY fecha DESC, created_at DESC LIMIT 200")

pg("PG Movimientos Save1", "40f23c5d-4e97-4812-a674-e5d75136dcd0", [8000, 4144], "INSERT INTO movimientos (org_id, tipo, descripcion, monto, fecha) VALUES ('{{ $json.org_id }}','{{ $json.tipo }}','{{ $json.descripcion }}',{{ $json.monto }},'{{ $json.fecha }}'::DATE) RETURNING *")

pg("PG Movimientos Delete1", "9b801faa-68ea-4168-a6e0-1a2eb96a5c65", [8000, 4320], "DELETE FROM movimientos WHERE id = {{ $json.id }} AND org_id = '{{ $json.org_id }}' RETURNING id")

C("WH Movimientos1", [[("Extract Movimientos1", 0)]])
C("Extract Movimientos1", [[("SW Movimientos1", 0)]])
C("SW Movimientos1", [[("PG Movimientos GetAll1", 0)], [("PG Movimientos Save1", 0)], [("PG Movimientos Delete1", 0)]])
C("PG Movimientos GetAll1", [[("Resp Movimientos1", 0)]])
C("PG Movimientos Save1", [[("Resp Movimientos1", 0)]])
C("PG Movimientos Delete1", [[("Resp Movimientos1", 0)]])

print("movimientos section ok:", len(nodes), "nodes")

# ============================================================================
# CONFIGURACION — con rama pública (getPublic) que reservar.html puede
# llamar sin login, y que solo devuelve nombre/rubro, nunca secretos.
# ============================================================================
webhook("WH Config1", "agenda-configuracion", "efdebda5-d096-4445-82c2-b2f614d98537", [10608, 4208], "30b329d1-a01a-4dcb-9206-82b9d66f332e")

code("Extract Config1", "f252a797-9d1f-465a-b2f6-50b7a235d089", [10832, 4208], r"""%s%s
const b = $input.first().json.body;
const d = b.data || b;
const org_id = String(b.org_id || '').replace(/[^a-z0-9\-_]/gi,'').slice(0,50);
const action = String(b.action || '').replace(/[^a-z0-9_]/gi,'').slice(0,30);

if (action === 'getPublic') {
  return [{ json: { action, org_id } }];
}

guardTenant($input.first().json.headers, org_id);
return [{ json: {
  action, org_id,
  data_datos: JSON.stringify(d || {}).replace(/'/g, "''"),
} }];""" % (api_key_check(), JWT_BLOCK))

switch("SW Config1", "8b1bbc86-c709-4a16-841b-8be97d37d3db", [11056, 4208],
       [("getAll", "getAll"), ("save", "save"), ("getPublic", "getPublic")])

resp("Resp Config1", "ad6187b9-68de-4887-bee4-2c96bf6015d7", [11504, 4080], RESP_OK)

pg("PG Config Get1", "c72042ac-9484-4b73-a141-705736eb3b28", [11280, 4080], "SELECT datos FROM configuracion WHERE org_id = '{{ $json.org_id }}'")

pg("PG Config Save1", "c012f556-890c-4267-8cea-57e5d7774aa6", [11264, 4272], "INSERT INTO configuracion (org_id, datos, updated_at) VALUES ('{{ $json.org_id }}','{{ $json.data_datos }}',NOW()) ON CONFLICT (org_id) DO UPDATE SET datos=EXCLUDED.datos, updated_at=NOW() RETURNING org_id")

pg("PG Config Get Public", "b1c1d1e1-0001-4001-8001-000000000001", [11280, 4400], "SELECT jsonb_build_object('nombre', datos->>'nombre', 'rubro', datos->>'rubro') AS resultado FROM configuracion WHERE org_id = '{{ $json.org_id }}'")

code("Format Config Public", "b1c1d1e1-0002-4002-8002-000000000002", [11504, 4400], r"""const raw = $input.first()?.json?.resultado;
const r = typeof raw === 'string' ? JSON.parse(raw) : (raw || {});
return [{ json: { ok: true, nombre: r.nombre || '', rubro: r.rubro || '' } }];""")

resp("Resp Config Public", "b1c1d1e1-0003-4003-8003-000000000003", [11728, 4400], "={{ JSON.stringify($json) }}")

C("WH Config1", [[("Extract Config1", 0)]])
C("Extract Config1", [[("SW Config1", 0)]])
C("SW Config1", [[("PG Config Get1", 0)], [("PG Config Save1", 0)], [("PG Config Get Public", 0)]])
C("PG Config Get1", [[("Resp Config1", 0)]])
C("PG Config Save1", [[("Resp Config1", 0)]])
C("PG Config Get Public", [[("Format Config Public", 0)]])
C("Format Config Public", [[("Resp Config Public", 0)]])

print("config section ok:", len(nodes), "nodes")

# ============================================================================
# DASHBOARD
# ============================================================================
webhook("WH Dashboard", "agenda-dashboard", "c0a37bce-6b99-4153-8546-78d119f48894", [10576, 3584], "3db09bf4-0be0-4255-b9a1-925506d3ccb5")

code("Extract Dashboard", "d408467c-d00b-4469-8903-8ee9f11d25d5", [10848, 3584], r"""%s%s
const b = $input.first().json.body;
const org_id = String(b.org_id || '').replace(/[^a-z0-9\-_]/gi,'').slice(0,50);
guardTenant($input.first().json.headers, org_id);
return [{ json: { org_id } }];""" % (api_key_check(), JWT_BLOCK))

pg("PG Dash Todo", "43d071e2-fdce-400a-95ac-baefbd60c7c0", [11120, 3584], r"""SELECT
  json_build_object(
    'reservas_hoy',    (SELECT COUNT(*) FROM reservas WHERE org_id='{{ $json.org_id }}' AND DATE(fecha_inicio)=CURRENT_DATE AND estado!='cancelada'),
    'reservas_mes',    (SELECT COUNT(*) FROM reservas WHERE org_id='{{ $json.org_id }}' AND DATE_TRUNC('month',fecha_inicio)=DATE_TRUNC('month',NOW()) AND estado!='cancelada'),
    'total_reservas',  (SELECT COUNT(*) FROM reservas WHERE org_id='{{ $json.org_id }}'),
    'tasa_asistencia', (SELECT COALESCE(ROUND(100.0*COUNT(*) FILTER (WHERE estado='completada')/NULLIF(COUNT(*) FILTER (WHERE estado!='cancelada'),0),0),0) FROM reservas WHERE org_id='{{ $json.org_id }}'),
    'ingresos_hoy',    (SELECT COALESCE(SUM(monto),0) FROM reservas WHERE org_id='{{ $json.org_id }}' AND DATE(fecha_inicio)=CURRENT_DATE AND estado!='cancelada'),
    'ingresos_semana', (SELECT COALESCE(SUM(monto),0) FROM reservas WHERE org_id='{{ $json.org_id }}' AND DATE_TRUNC('week',fecha_inicio)=DATE_TRUNC('week',NOW()) AND estado!='cancelada'),
    'ingresos_mes',    (SELECT COALESCE(SUM(monto),0) FROM reservas WHERE org_id='{{ $json.org_id }}' AND DATE_TRUNC('month',fecha_inicio)=DATE_TRUNC('month',NOW()) AND estado!='cancelada'),
    'ingresos_anio',   (SELECT COALESCE(SUM(monto),0) FROM reservas WHERE org_id='{{ $json.org_id }}' AND DATE_TRUNC('year',fecha_inicio)=DATE_TRUNC('year',NOW()) AND estado!='cancelada'),
    'egresos_mes',     (SELECT COALESCE(SUM(monto),0) FROM movimientos WHERE org_id='{{ $json.org_id }}' AND tipo='eg' AND DATE_TRUNC('month',fecha)=DATE_TRUNC('month',NOW())),
    'semana', (SELECT json_agg(s) FROM (SELECT DATE(fecha_inicio)::text AS dia, COUNT(*)::int AS total FROM reservas WHERE org_id='{{ $json.org_id }}' AND fecha_inicio >= NOW() - INTERVAL '7 days' AND estado!='cancelada' GROUP BY DATE(fecha_inicio) ORDER BY dia) s),
    'hoy',    (SELECT json_agg(h) FROM (SELECT id, cliente_nombre, servicio_nombre, profesional_nombre, fecha_inicio::text, fecha_fin::text, estado, monto FROM reservas WHERE org_id='{{ $json.org_id }}' AND DATE(fecha_inicio)=CURRENT_DATE AND estado!='cancelada' ORDER BY fecha_inicio) h)
  ) AS resultado""")

code("Merge Dashboard", "c227a5bd-4ce8-4cdb-bcf2-899be23fb199", [11360, 3584], r"""const raw = $input.first().json.resultado;
const r = typeof raw === 'string' ? JSON.parse(raw) : raw;
return [{
  json: {
    ok: true,
    metricas: {
      reservas_hoy:    parseInt(r.reservas_hoy    || 0),
      reservas_mes:    parseInt(r.reservas_mes    || 0),
      total_reservas:  parseInt(r.total_reservas  || 0),
      tasa_asistencia: parseInt(r.tasa_asistencia || 0),
      ingresos_hoy:    parseFloat(r.ingresos_hoy    || 0),
      ingresos_semana: parseFloat(r.ingresos_semana || 0),
      ingresos_mes:    parseFloat(r.ingresos_mes    || 0),
      ingresos_anio:   parseFloat(r.ingresos_anio   || 0),
      egresos_mes:     parseFloat(r.egresos_mes     || 0)
    },
    semana: r.semana || [],
    hoy:    r.hoy    || []
  }
}];""")

resp("Resp Dashboard", "8d155873-ada8-4f27-9551-daf684741069", [11600, 3584], "={{ JSON.stringify($json) }}")

C("WH Dashboard", [[("Extract Dashboard", 0)]])
C("Extract Dashboard", [[("PG Dash Todo", 0)]])
C("PG Dash Todo", [[("Merge Dashboard", 0)]])
C("Merge Dashboard", [[("Resp Dashboard", 0)]])

print("dashboard section ok:", len(nodes), "nodes")

# ============================================================================
# SLOTS (público — disponibilidad real, sin login)
# ============================================================================
webhook("WH Slots", "agenda-slots", "7b008076-4ec1-46f3-a8bf-39f4099c70e5", [11952, 4192], "7c4a2b1d-8e9f-4a3b-bc6d-1e2f3a4b5c6d")

code("Extract Slots", "ca454b40-4b0d-4855-9367-36c1dd990e0d", [12144, 4192], r"""%s
const b = $input.first().json.body;
return [{ json: {
  org_id: String(b.org_id || '').replace(/[^a-z0-9\-_]/gi,'').slice(0,50),
  profesional_id: parseInt(b.profesional_id || 0),
  fecha: String(b.fecha || '').slice(0,10),
  duracion_min: parseInt(b.duracion_min || 60)
} }];""" % api_key_check())

pg("PG Slots", "279e0a56-1c0b-4863-9c97-18296ba7e036", [12352, 4192], r"""SELECT
  to_char(slot_time, 'HH24:MI') AS hora,
  slot_time::text AS fecha_inicio,
  (slot_time + ({{ $json.duracion_min }} || ' minutes')::interval)::text AS fecha_fin,
  NOT EXISTS (
    SELECT 1 FROM reservas r
    WHERE r.org_id = '{{ $json.org_id }}'
      AND r.estado != 'cancelada'
      AND (CASE WHEN {{ $json.profesional_id }} > 0 THEN r.profesional_id = {{ $json.profesional_id }} ELSE true END)
      AND tstzrange(r.fecha_inicio::timestamptz, r.fecha_fin::timestamptz, '[)') &&
          tstzrange(slot_time::timestamptz, (slot_time + ({{ $json.duracion_min }} || ' minutes')::interval)::timestamptz, '[)')
  ) AS disponible
FROM generate_series(
  ('{{ $json.fecha }}'::date + '08:00'::time)::timestamp,
  ('{{ $json.fecha }}'::date + '20:00'::time)::timestamp - ({{ $json.duracion_min }} || ' minutes')::interval,
  '30 minutes'::interval
) AS slot_time
WHERE '{{ $json.fecha }}'::date >= CURRENT_DATE
  AND (
    '{{ $json.fecha }}'::date > CURRENT_DATE
    OR slot_time::time > (NOW()::time + '30 minutes'::interval)
  )
ORDER BY slot_time""")

resp("Resp Slots", "99143aa5-8b0d-4021-b582-4b3949c64de4", [12560, 4192], RESP_OK)

C("WH Slots", [[("Extract Slots", 0)]])
C("Extract Slots", [[("PG Slots", 0)]])
C("PG Slots", [[("Resp Slots", 0)]])

print("slots section ok:", len(nodes), "nodes")

# ============================================================================
# RESERVA PÚBLICA (reservar.html) — llama a agenda-reservas internamente,
# ahora con el token de servicio propio (no hace falta JWT de usuario porque
# es server-to-server, dentro de la misma instancia n8n).
# ============================================================================
webhook("Reserva pública", "agenda-public-booking", "dd60d9fc-5f16-4aa8-aed4-114117bb0878", [10720, 2128], "ffabef35-7623-46b3-ae4a-3b38c55bd85f")

code("Validar y preparar reserva", "06e76e27-0bf8-4507-8f8c-c5313a604d1b", [10992, 2128], r"""%s
const body = $json.body || $json;
const required = ['org_id', 'nombre', 'telefono', 'servicio_id', 'fecha', 'hora'];
for (const field of required) { if (!body[field]) throw new Error(`Falta campo requerido: ${field}`); }

function clean(v){ return String(v || '').trim(); }
function esc(v, max){ return String(v||'').replace(/[<>"'&]/g,'').slice(0,max||100); }
function extractId(v){
  const raw = String(v || '').trim();
  const match = raw.match(/(\d+)$/);
  return match ? parseInt(match[1], 10) : parseInt(raw, 10) || 0;
}

const org_id = String(body.org_id||'').replace(/[^a-z0-9\-_]/gi,'').slice(0,50);
const nombre = esc(body.nombre, 100);
const telefono = String(body.telefono||'').replace(/[^0-9+\s]/g,'').slice(0,20);
const servicio_id = extractId(body.servicio_id);
const profesional_id = extractId(body.profesional_id);
const fecha = clean(body.fecha).slice(0,10);
const hora = clean(body.hora).slice(0,5);

const fecha_inicio = `${fecha}T${hora}:00`;
const duracionMin = parseInt(body.duracion_min || 60, 10);
function addMinutes(isoStr, mins){
  const [datePart, timePart] = isoStr.split('T');
  const [h, m] = timePart.replace(':00','').split(':').map(Number);
  const total = h * 60 + (m||0) + mins;
  const nh = Math.floor(total/60) %% 24;
  const nm = total %% 60;
  return `${datePart}T${String(nh).padStart(2,'0')}:${String(nm).padStart(2,'0')}:00`;
}
const fecha_fin = addMinutes(fecha_inicio, duracionMin);

const reserva = {
  cliente_nombre: nombre, cliente_tel: telefono,
  servicio_id, servicio_nombre: esc(body.servicio_nombre || 'Servicio reservado desde web', 100),
  profesional_id, profesional_nombre: esc(body.profesional_nombre, 100),
  fecha_inicio, fecha_fin,
  monto: parseFloat(body.monto || 0),
  estado: 'pendiente', origen: 'pagina_web',
  notas: esc(body.notas || 'Reserva creada desde página pública', 300)
};

return [{ json: { ok: true, org_id, reserva, fecha, hora } }];""" % api_key_check())

httpreq("Crear cita en AgendaOS", "94b8b1b6-c0b2-4c04-a4b8-e235a8ff750a", [11264, 2128],
        "https://n8n-n8n.fa2cjf.easypanel.host/webhook/agenda-reservas",
        [{"name": "Content-Type", "value": "application/json"},
         {"name": "x-api-key", "value": "={{ $env.AUTIX_API_KEY }}"},
         {"name": "x-internal-key", "value": "={{ $env.N8N_INTERNAL_KEY }}"}],
        "={{ { org_id: $json.org_id, action: 'save', data: $json.reserva } }}")

code("Preparar respuesta", "a4f5ebf5-2ff2-47ca-8289-21c383521c5c", [11520, 2128], r"""const saved = $json;
if (saved && saved.ok === false) {
  return [{ json: { ok: false, message: saved.error || 'No fue posible crear la reserva' } }];
}
return [{ json: { ok: true, message: 'Reserva recibida correctamente. Recibirás confirmación por WhatsApp.' } }];""")

resp("Responder a la web", "b9440d95-b85c-4f71-a21b-949d0ddaea7e", [11792, 2128], "={{ $json }}")

C("Reserva pública", [[("Validar y preparar reserva", 0)]])
C("Validar y preparar reserva", [[("Crear cita en AgendaOS", 0)]])
C("Crear cita en AgendaOS", [[("Preparar respuesta", 0)]])
C("Preparar respuesta", [[("Responder a la web", 0)]])

print("public booking section ok:", len(nodes), "nodes")

# ============================================================================
# CREAR PAGO + NOTIFICACION MERCADOPAGO — token en env var, idempotencia real
# ============================================================================
webhook("WH Crear Pago", "agenda-crear-pago", "09dd384f-f758-43d8-a2c6-be60699f12e2", [5648, 4448], "c1d2e3f4-a5b6-7890-cdef-012345678901")

code("Extract Pago", "cb14322b-bf61-4fe3-8988-951f35d8870c", [5888, 4448], r"""%s%s
const b = $input.first().json.body;
const plan = b.plan === 'anual' ? 'anual' : 'mensual';
const org_id = String(b.org_id || '').replace(/[^a-z0-9\-_]/gi,'').slice(0,50);
if (!org_id) throw new Error('org_id requerido');
guardTenant($input.first().json.headers, org_id); // solo el dueño de la sesión paga su propio plan
return [{ json: { org_id, plan } }];""" % (api_key_check(), JWT_BLOCK))

httpreq("MP Crear Preferencia", "526852c8-179c-469f-9d9b-2f71dcdad22e", [6128, 4448],
        "https://api.mercadopago.com/checkout/preferences",
        [{"name": "Authorization", "value": "=Bearer {{ $env.MP_ACCESS_TOKEN }}"},
         {"name": "Content-Type", "value": "application/json"}],
        "={{ JSON.stringify({\n  items: [{\n    id: $json.plan,\n    title: $json.plan === 'anual' ? 'AgendaOS Plan Pro · Anual' : 'AgendaOS Plan Pro · Mensual',\n    description: $json.plan === 'anual' ? '12 meses de AgendaOS Pro (20% descuento)' : '1 mes de AgendaOS Pro',\n    quantity: 1,\n    currency_id: 'CLP',\n    unit_price: $json.plan === 'anual' ? 95904 : 9990\n  }],\n  back_urls: {\n    success: 'https://app.agendaos.pro?pago=ok&org=' + $json.org_id + '&plan=' + $json.plan,\n    failure: 'https://app.agendaos.pro?pago=error',\n    pending: 'https://app.agendaos.pro?pago=pendiente'\n  },\n  auto_return: 'approved',\n  external_reference: $json.org_id + '|' + $json.plan,\n  notification_url: 'https://n8n-n8n.fa2cjf.easypanel.host/webhook/agenda-mp-notify',\n  expires: false\n}) }}")

code("Resp Preferencia", "e133a5c7-0a9b-4bc3-a3d0-d9ab3c52bddd", [6368, 4448], r"""const r = $input.first().json;
if (!r.id) return [{ json: { ok: false, error: 'Error creando preferencia MP' } }];
return [{ json: { ok: true, checkout_url: r.init_point, preference_id: r.id } }];""")

resp("Resp Crear Pago", "90b60d52-a470-46b3-88f3-2df486284fb5", [6608, 4448], "={{ JSON.stringify($json) }}")

webhook("WH MP Notify", "agenda-mp-notify", "d43d67a5-0a54-4341-b18c-c5950ffd27d3", [5648, 4720], "d2e3f4a5-b6c7-8901-defa-123456789012")

resp("Resp Notify Fast", "589f8d9d-b5bf-4fc1-b0dd-dc9988e1ac96", [5872, 4944], "{\"ok\":true}")

code("Extract Notify", "d1245ef2-6894-464c-8663-93cb104786c8", [5888, 4720], r"""const b = $input.first().json.body || $input.first().json;
const topic = b.topic || b.type || '';
const id = b.data?.id || b.id || '';
if (!['payment','merchant_order'].includes(topic) && b.type !== 'payment') return [{ json: { skip: true } }];
return [{ json: { skip: false, payment_id: String(id).replace(/[^0-9]/g,''), topic } }];""")

switch2 = None
N(parameters={
    "rules": {"values": [
        {"conditions": {"conditions": [{"leftValue": "={{ $json.skip }}", "rightValue": True, "operator": {"type": "boolean", "operation": "equals"}}], "combinator": "and", "options": {"caseSensitive": True, "leftValue": "", "typeValidation": "strict", "version": 1}}, "renameOutput": True, "outputKey": "skip"},
        {"conditions": {"conditions": [{"leftValue": "={{ $json.skip }}", "rightValue": False, "operator": {"type": "boolean", "operation": "equals"}}], "combinator": "and", "options": {"caseSensitive": True, "leftValue": "", "typeValidation": "strict", "version": 1}}, "renameOutput": True, "outputKey": "process"}
    ]}, "options": {}
}, id="51cf5ff0-2640-459a-8c16-6a44bef522e1", name="SW Notify", type="n8n-nodes-base.switch", typeVersion=3.2, position=[6128, 4720])

httpreq("MP Get Payment", "330b023c-ed85-45e9-b28c-bffbd116b3df", [6368, 4816],
        "=https://api.mercadopago.com/v1/payments/{{ $json.payment_id }}",
        [{"name": "Authorization", "value": "=Bearer {{ $env.MP_ACCESS_TOKEN }}"}],
        None, method="GET")
nodes[-1]["parameters"].pop("sendBody", None)
nodes[-1]["parameters"].pop("specifyBody", None)
nodes[-1]["parameters"].pop("jsonBody", None)
nodes[-1]["parameters"]["sendBody"] = False

code("Check Payment", "d71e8735-8142-445c-835b-0fabe52521f9", [6608, 4816], r"""const p = $input.first().json;
if (p.status !== 'approved') return [{ json: { skip: true, status: p.status } }];
const ref = p.external_reference || '';
const [org_id, plan] = ref.split('|');
if (!org_id) return [{ json: { skip: true, error: 'sin org_id' } }];
const expira = plan === 'anual'
  ? new Date(Date.now() + 365*24*60*60*1000).toISOString()
  : new Date(Date.now() + 30*24*60*60*1000).toISOString();
return [{ json: { skip: false, org_id, plan, expira, payment_id: String(p.id), monto: p.transaction_amount } }];""")

N(parameters={
    "rules": {"values": [
        {"conditions": {"conditions": [{"leftValue": "={{ $json.skip }}", "rightValue": False, "operator": {"type": "boolean", "operation": "equals"}}], "combinator": "and", "options": {"caseSensitive": True, "leftValue": "", "typeValidation": "strict", "version": 1}}, "renameOutput": True, "outputKey": "activar"},
        {"conditions": {"conditions": [{"leftValue": "={{ $json.skip }}", "rightValue": True, "operator": {"type": "boolean", "operation": "equals"}}], "combinator": "and", "options": {"caseSensitive": True, "leftValue": "", "typeValidation": "strict", "version": 1}}, "renameOutput": True, "outputKey": "skip"}
    ]}, "options": {}
}, id="46b79b42-f204-453c-9861-9866fcc9852b", name="SW Activar", type="n8n-nodes-base.switch", typeVersion=3.2, position=[6848, 4816])

pg("PG Activar Plan", "cb3fed07-7644-4f08-bf29-1913cfb8cbe9", [7088, 4720], r"""WITH nuevo AS (
  INSERT INTO pagos_procesados (payment_id, org_id)
  VALUES ('{{ $json.payment_id }}', '{{ $json.org_id }}')
  ON CONFLICT (payment_id) DO NOTHING
  RETURNING org_id
)
UPDATE negocios
SET plan_activo = 'pro', trial_expira = '{{ $json.expira }}'::timestamptz, updated_at = NOW()
WHERE org_id = (SELECT org_id FROM nuevo)
RETURNING org_id, nombre, email, plan_activo, trial_expira::text""")

N(parameters={
    "fromEmail": "info@autix.pro", "toEmail": "={{ $json.email }}", "subject": "✅ Plan Pro activado · AgendaOS",
    "html": "=<h2>¡Tu plan Pro está activo!</h2><p>Hola <b>{{ $json.nombre }}</b>, tu pago fue procesado correctamente.</p><ul><li><b>Plan:</b> Pro</li><li><b>Válido hasta:</b> {{ $json.trial_expira }}</li><li><b>Acceso:</b> <a href='https://app.agendaos.pro'>https://app.agendaos.pro</a></li></ul><p>Gracias por confiar en AgendaOS.</p>",
    "options": {}
}, id="256fd5d3-e88e-4723-ac19-f5615e0a2b38", name="Email Confirmacion", type="n8n-nodes-base.emailSend",
   typeVersion=2.1, position=[7328, 4720], webhookId="e4009ca8-b35d-4f37-9313-be868cb0c255",
   credentials={"smtp": {"id": "yg5JS5bayhagsQSE", "name": "SMTP account"}})

C("WH Crear Pago", [[("Extract Pago", 0)]])
C("Extract Pago", [[("MP Crear Preferencia", 0)]])
C("MP Crear Preferencia", [[("Resp Preferencia", 0)]])
C("Resp Preferencia", [[("Resp Crear Pago", 0)]])
C("WH MP Notify", [[("Resp Notify Fast", 0), ("Extract Notify", 0)]])
C("Extract Notify", [[("SW Notify", 0)]])
C("SW Notify", [[], [("MP Get Payment", 0)]])
C("MP Get Payment", [[("Check Payment", 0)]])
C("Check Payment", [[("SW Activar", 0)]])
C("SW Activar", [[("PG Activar Plan", 0)]])
C("PG Activar Plan", [[("Email Confirmacion", 0)]])

print("pagos section ok:", len(nodes), "nodes")

# ============================================================================
# WHATSAPP — envío manual desde el panel (campañas)
# ============================================================================
webhook("WH WhatsApp", "agenda-whatsapp", "71f50f3d-f693-4413-8895-110a4698c040", [8928, 1776], "a1b2c3d4-e5f6-7890-abcd-ef1234567890")

code("Extract WA", "7a73e273-b8f5-45ef-b792-2fd33995a7f1", [9168, 1776], r"""%s%s
const b = $input.first().json.body;
const org_id = String(b.org_id || '').replace(/[^a-z0-9\-_]/gi,'').slice(0,50);
guardTenant($input.first().json.headers, org_id);
return [{ json: {
  action:   String(b.action || 'send'),
  org_id,
  telefono: String(b.telefono || '').replace(/[^0-9+]/g,'').slice(0,20),
  mensaje:  String(b.mensaje || '').slice(0,1000)
} }];""" % (api_key_check(), JWT_BLOCK))

pg("PG Get Evo Config", "e38e86ce-9bd3-4577-869f-a0447054bd37", [9408, 1776], "SELECT datos->>'evo_url' AS evo_url, datos->>'evo_key' AS evo_key, datos->>'evo_instancia' AS evo_instancia FROM configuracion WHERE org_id='{{ $json.org_id }}' LIMIT 1")

code("Prepare WA Send", "48b4337e-221b-4396-9163-39c14cce26ad", [9648, 1776], r"""const cfg = $('PG Get Evo Config').first().json;
const req = $('Extract WA').first().json;

if (!cfg.evo_url || !cfg.evo_key || !cfg.evo_instancia) {
  return [{ json: { ok: false, error: 'Evolution API no configurada para este negocio' } }];
}

let tel = req.telefono.replace(/[^0-9]/g,'');
if (tel.startsWith('9') && tel.length === 9) tel = '56' + tel;
if (tel.startsWith('0')) tel = tel.slice(1);

return [{ json: {
  evo_url: cfg.evo_url.replace(/\/$/,''),
  evo_key: cfg.evo_key,
  evo_instancia: cfg.evo_instancia,
  telefono: tel,
  mensaje: req.mensaje
} }];""")

httpreq("Send WA Message", "b80894f3-29fc-4ca5-bfd7-d601fd586dbf", [9888, 1776],
        "={{ $json.evo_url }}/message/sendText/{{ $json.evo_instancia }}",
        [{"name": "apikey", "value": "={{ $json.evo_key }}"}, {"name": "Content-Type", "value": "application/json"}],
        "={{ JSON.stringify({ number: $json.telefono, textMessage: { text: $json.mensaje } }) }}")
nodes[-1]["parameters"]["options"] = {"timeout": 10000}

code("WA Response", "9501e7ec-bff6-4e50-b5c8-8d8aec7eca4f", [10128, 1776], r"""const r = $input.first().json;
if (r.key || r.message?.key) return [{ json: { ok: true, message: 'Mensaje enviado' } }];
return [{ json: { ok: false, error: 'Error al enviar' } }];""")

resp("Resp WA", "8bdb23a7-2c7a-4d2b-97c4-eea11d7b0bac", [10368, 1776], "={{ JSON.stringify($json) }}")

C("WH WhatsApp", [[("Extract WA", 0)]])
C("Extract WA", [[("PG Get Evo Config", 0)]])
C("PG Get Evo Config", [[("Prepare WA Send", 0)]])
C("Prepare WA Send", [[("Send WA Message", 0)]])
C("Send WA Message", [[("WA Response", 0)]])
C("WA Response", [[("Resp WA", 0)]])

print("whatsapp manual section ok:", len(nodes), "nodes")

# ============================================================================
# AGENTE IA POR WHATSAPP (Evolution API) — antes NO tenía ninguna
# autenticación y era inyectable vía 'instancia'/'pushName'. Ahora exige un
# secreto compartido en la URL del webhook y sanea todo el payload externo
# antes de tocar SQL o el prompt del modelo.
# ============================================================================
N(parameters={"httpMethod": "POST", "path": "agenda-agente-wa", "responseMode": "responseNode", "options": {}},
  id="99a68b06-a5e8-4501-a1b6-aecbcb316761", name="WH Evolution API", type="n8n-nodes-base.webhook",
  typeVersion=2.1, position=[7536, 5136], webhookId="b1c2d3e4-f5a6-7890-bcde-f12345678901")

code("Parse Mensaje", "275501c0-a517-4de3-aee2-070759ad2d8c", [7776, 5136], r"""const WEBHOOK_SECRET = $env.WA_AGENT_WEBHOOK_SECRET;
const query = $input.first().json.query || {};
if (String(query.secret || '') !== WEBHOOK_SECRET) {
  return [{ json: { skip: true, reason: 'unauthorized' } }];
}

const body = $input.first().json.body || $input.first().json;
const event = body.event || body.type || '';
const msg = body.data?.message || body.message || {};
const key = body.data?.key || body.key || {};
const fromMe = key.fromMe || msg.fromMe || false;

if (fromMe) return [{ json: { skip: true, reason: 'mensaje propio' } }];
if (!['messages.upsert','message'].some(e => event.includes(e) || body.event === e)) {
  if (!body.data?.message && !body.message) return [{ json: { skip: true, reason: 'no es mensaje' } }];
}

// Todo lo que sigue viene de un payload externo: nunca confiar sin sanear antes de SQL/prompt
const instancia = String(body.instance || body.instanceName || 'default').replace(/[^a-zA-Z0-9_\-]/g, '').slice(0, 50);
const telefono  = String(key.remoteJid || body.data?.key?.remoteJid || '').replace(/@.*/, '').replace(/[^0-9]/g, '').slice(0, 20);
const texto     = String(msg.conversation || msg.extendedTextMessage?.text || body.data?.message?.conversation || '').slice(0, 1000);
const pushName  = String(body.data?.pushName || body.pushName || '').replace(/[<>"'&\\]/g, '').slice(0, 100);

if (!telefono || !texto) return [{ json: { skip: true, reason: 'sin telefono o texto' } }];

return [{ json: { skip: false, instancia, telefono, texto, pushName, session_id: instancia + '_' + telefono } }];""")

N(parameters={
    "rules": {"values": [
        {"conditions": {"conditions": [{"leftValue": "={{ $json.skip }}", "rightValue": True, "operator": {"type": "boolean", "operation": "equals"}}], "combinator": "and", "options": {"caseSensitive": True, "leftValue": "", "typeValidation": "strict", "version": 1}}, "renameOutput": True, "outputKey": "skip"},
        {"conditions": {"conditions": [{"leftValue": "={{ $json.skip }}", "rightValue": False, "operator": {"type": "boolean", "operation": "equals"}}], "combinator": "and", "options": {"caseSensitive": True, "leftValue": "", "typeValidation": "strict", "version": 1}}, "renameOutput": True, "outputKey": "process"}
    ]}, "options": {}
}, id="a4d6d896-f93c-4fcb-a2cb-2a61c0931e5e", name="Skip o Procesar", type="n8n-nodes-base.switch", typeVersion=3.4, position=[8016, 5136])

resp("Resp Skip", "2215c335-1662-4f61-aeab-4a7c7bfd9bfc", [8256, 4992], "={\"ok\":true}")

pg("PG Get Org", "23fb95b1-3838-4ad0-9d62-a1232fe0fbce", [8256, 5216], r"""SELECT
  n.org_id,
  n.nombre AS negocio_nombre,
  cfg.datos->>'evo_url' AS evo_url,
  cfg.datos->>'evo_key' AS evo_key,
  cfg.datos->>'evo_instancia' AS evo_instancia,
  cfg.datos->>'direccion' AS direccion,
  cfg.datos->>'horario' AS horario,
  cfg.datos->>'msg_recordatorio' AS msg_recordatorio,
  cfg.datos->>'anthropic_key' AS anthropic_key
FROM negocios n
LEFT JOIN configuracion cfg ON cfg.org_id = n.org_id
WHERE cfg.datos->>'evo_instancia' = '{{ $json.instancia }}'
   OR n.org_id = '{{ $json.instancia }}'
LIMIT 1""")

pg("PG Get Contexto", "9ded7200-a12e-477f-a2a2-975333d0dea2", [8496, 5216], r"""SELECT 'servicios' AS tipo, json_agg(json_build_object('nombre',nombre,'precio',precio,'duracion',duracion_min)) AS data
FROM servicios WHERE org_id='{{ $json.org_id }}' AND activo=true
UNION ALL
SELECT 'profesionales', json_agg(json_build_object('nombre',nombre))
FROM profesionales WHERE org_id='{{ $json.org_id }}'
UNION ALL
SELECT 'historial_cliente', json_agg(json_build_object('servicio',servicio_nombre,'fecha',fecha_inicio::text,'estado',estado) ORDER BY fecha_inicio DESC)
FROM (SELECT * FROM reservas WHERE org_id='{{ $json.org_id }}' AND cliente_tel='{{ $json.telefono }}' ORDER BY fecha_inicio DESC LIMIT 5) r
UNION ALL
SELECT 'memoria', json_agg(json_build_object('role',role,'content',content) ORDER BY created_at ASC)
FROM (SELECT * FROM agent_memory WHERE session_id='{{ $json.session_id }}' ORDER BY created_at DESC LIMIT 10) m""")

code("Build Prompt", "265fe5ea-79f0-44f6-981d-3a1cb38629b7", [8736, 5216], r"""const parse = $('Parse Mensaje').first().json;
const org = $('PG Get Org').first().json;
const rows = $input.all().map(i => i.json);

const ctx = {};
for (const row of rows) {
  try { ctx[row.tipo] = typeof row.data === 'string' ? JSON.parse(row.data) : row.data; }
  catch (e) { ctx[row.tipo] = []; }
}

const servicios = (ctx.servicios || []).map(s => `- ${s.nombre}: $${s.precio} (${s.duracion} min)`).join('\n');
const profesionales = (ctx.profesionales || []).map(p => p.nombre).join(', ');
const historial = (ctx.historial_cliente || []).map(h => `${h.fecha?.slice(0,10)}: ${h.servicio} (${h.estado})`).join('\n');
const memoria = ctx.memoria || [];

const SYSTEM = `Eres el asistente virtual de ${org.negocio_nombre || 'este negocio'}. Atiendes por WhatsApp de forma amigable, directa y en español chileno informal.

NEGOCIO:
- Nombre: ${org.negocio_nombre}
- Dirección: ${org.direccion || 'Consultar'}
- Horario: ${org.horario || 'Lunes a Sábado 9:00-20:00'}

SERVICIOS Y PRECIOS:
${servicios || 'Sin servicios registrados'}

PROFESIONALES: ${profesionales || 'Sin profesionales registrados'}

HISTORIAL DEL CLIENTE:
${historial || 'Cliente nuevo'}

LINK DE RESERVA ONLINE: https://app.agendaos.pro/reservar.html?negocio=${org.org_id}

INSTRUCCIONES:
- Responde siempre en español chileno informal (tú, no usted)
- Sé breve — máximo 3-4 líneas por respuesta
- Si quieren agendar, dales el link de reserva o usa la tool crear_reserva
- Si preguntan precio, responde directo con el precio
- Si preguntan disponibilidad, usa la tool ver_disponibilidad
- Para cancelar o modificar cita, usa la tool actualizar_reserva
- Si no puedes resolver algo, di que un humano los contactará pronto
- NUNCA inventes precios o servicios que no estén en la lista`;

const messages = [
  ...memoria.map(m => ({role: m.role, content: m.content})),
  {role: 'user', content: parse.texto}
];

return [{ json: {
  ...parse, ...org, system: SYSTEM, messages,
  tools: [
    { name: 'ver_disponibilidad', description: 'Ver horarios disponibles para una fecha. Usar cuando el cliente pregunta por disponibilidad o quiere agendar.',
      input_schema: { type: 'object', properties: { fecha: {type:'string', description:'Fecha en formato YYYY-MM-DD'}, servicio_nombre: {type:'string', description:'Nombre del servicio que quiere'} }, required: ['fecha'] } },
    { name: 'crear_reserva', description: 'Crear una nueva reserva para el cliente. Usar cuando el cliente confirma que quiere agendar con fecha y hora específica.',
      input_schema: { type: 'object', properties: { fecha: {type:'string', description:'YYYY-MM-DD'}, hora: {type:'string', description:'HH:MM'}, servicio_nombre: {type:'string'}, cliente_nombre: {type:'string'} }, required: ['fecha','hora','servicio_nombre'] } },
    { name: 'ver_mis_citas', description: 'Ver las próximas citas del cliente. Usar cuando el cliente pregunta por sus citas o quiere cancelar.',
      input_schema: {type:'object', properties: {}, required: []} },
    { name: 'cancelar_cita', description: 'Cancelar una cita existente del cliente.',
      input_schema: { type: 'object', properties: { cita_id: {type:'number', description:'ID de la cita a cancelar'} }, required: ['cita_id'] } }
  ]
} }];""")

httpreq("Claude API", "78cf5158-dc9e-4628-b2db-5a23bee89a30", [8976, 5216],
        "https://api.anthropic.com/v1/messages",
        [{"name": "x-api-key", "value": "={{ $json.anthropic_key || $env.ANTHROPIC_API_KEY }}"},
         {"name": "anthropic-version", "value": "2023-06-01"},
         {"name": "content-type", "value": "application/json"}],
        "={{ JSON.stringify({ model: 'claude-sonnet-4-20250514', max_tokens: 1024, system: $json.system, tools: $json.tools, messages: $json.messages }) }}")
nodes[-1]["parameters"]["options"] = {"timeout": 30000}

code("Check Tool Use", "35ea2fec-0440-475e-b958-dca8ede952c3", [9216, 5216], r"""const resp = $input.first().json;
const ctx = $('Build Prompt').first().json;

const content = resp.content || [];
const stopReason = resp.stop_reason;
const texto = content.filter(b=>b.type==='text').map(b=>b.text).join('');
const toolUse = content.filter(b=>b.type==='tool_use');

return [{ json: {
  ...ctx, respuesta_texto: texto, stop_reason: stopReason, tool_use: toolUse,
  necesita_tool: stopReason === 'tool_use' && toolUse.length > 0,
  response_content: content
} }];""")

N(parameters={
    "rules": {"values": [
        {"conditions": {"conditions": [{"leftValue": "={{ $json.necesita_tool }}", "rightValue": True, "operator": {"type": "boolean", "operation": "equals"}}], "combinator": "and", "options": {"caseSensitive": True, "leftValue": "", "typeValidation": "strict", "version": 1}}, "renameOutput": True, "outputKey": "tool"},
        {"conditions": {"conditions": [{"leftValue": "={{ $json.necesita_tool }}", "rightValue": False, "operator": {"type": "boolean", "operation": "equals"}}], "combinator": "and", "options": {"caseSensitive": True, "leftValue": "", "typeValidation": "strict", "version": 1}}, "renameOutput": True, "outputKey": "final"}
    ]}, "options": {}
}, id="6d92b971-d442-444f-86d8-9e1f6d337f01", name="Tool o Final", type="n8n-nodes-base.switch", typeVersion=3.4, position=[9456, 5216])

code("Route Tool", "39f4baba-18bb-43b7-b566-7b3e82282da1", [9696, 5072], r"""const ctx = $input.first().json;
const tool = ctx.tool_use[0];
const name = tool.name;
const input = { ...tool.input };
if (input.cita_id !== undefined) input.cita_id = parseInt(input.cita_id) || 0;
return [{ json: { ...ctx, tool_name: name, tool_input: input, org_id: ctx.org_id, telefono: ctx.telefono } }];""")

N(parameters={
    "rules": {"values": [
        {"conditions": {"conditions": [{"leftValue": "={{ $json.tool_name }}", "rightValue": "ver_disponibilidad", "operator": {"type": "string", "operation": "equals"}}], "combinator": "and", "options": {"caseSensitive": True, "leftValue": "", "typeValidation": "strict", "version": 1}}, "renameOutput": True, "outputKey": "disponibilidad"},
        {"conditions": {"conditions": [{"leftValue": "={{ $json.tool_name }}", "rightValue": "crear_reserva", "operator": {"type": "string", "operation": "equals"}}], "combinator": "and", "options": {"caseSensitive": True, "leftValue": "", "typeValidation": "strict", "version": 1}}, "renameOutput": True, "outputKey": "crear"},
        {"conditions": {"conditions": [{"leftValue": "={{ $json.tool_name }}", "rightValue": "ver_mis_citas", "operator": {"type": "string", "operation": "equals"}}], "combinator": "and", "options": {"caseSensitive": True, "leftValue": "", "typeValidation": "strict", "version": 1}}, "renameOutput": True, "outputKey": "mis_citas"},
        {"conditions": {"conditions": [{"leftValue": "={{ $json.tool_name }}", "rightValue": "cancelar_cita", "operator": {"type": "string", "operation": "equals"}}], "combinator": "and", "options": {"caseSensitive": True, "leftValue": "", "typeValidation": "strict", "version": 1}}, "renameOutput": True, "outputKey": "cancelar"}
    ]}, "options": {}
}, id="aa69cd71-90a7-43e7-8c25-4a8646818295", name="SW Tools", type="n8n-nodes-base.switch", typeVersion=3.4, position=[9936, 5072])

pg("PG Disponibilidad", "944d06d0-599b-466d-b327-e3e0b12e29a5", [10176, 4944], r"""SELECT
  to_char(slot_time, 'HH24:MI') AS hora,
  NOT EXISTS (
    SELECT 1 FROM reservas r
    WHERE r.org_id = '{{ $json.org_id }}'
      AND r.estado != 'cancelada'
      AND tstzrange(r.fecha_inicio::timestamptz, r.fecha_fin::timestamptz, '[)') &&
          tstzrange(slot_time::timestamptz, (slot_time + '60 minutes'::interval)::timestamptz, '[)')
  ) AS disponible
FROM generate_series(
  ('{{ $json.tool_input.fecha }}'::date + '09:00'::time)::timestamp,
  ('{{ $json.tool_input.fecha }}'::date + '19:00'::time)::timestamp,
  '30 minutes'::interval
) AS slot_time
WHERE '{{ $json.tool_input.fecha }}'::date >= CURRENT_DATE
ORDER BY slot_time""")

pg("PG Crear Reserva", "53810a60-30ae-4ec2-964d-000da443cccf", [10176, 5104], r"""WITH conflict_check AS (
  SELECT COUNT(*) AS cnt FROM reservas
  WHERE org_id = '{{ $json.org_id }}' AND estado != 'cancelada'
    AND tstzrange(fecha_inicio::timestamptz, fecha_fin::timestamptz, '[)') &&
        tstzrange(('{{ $json.tool_input.fecha }}'::date + '{{ $json.tool_input.hora }}'::time)::timestamptz,
                  (('{{ $json.tool_input.fecha }}'::date + '{{ $json.tool_input.hora }}'::time) + interval '60 minutes')::timestamptz, '[)')
)
INSERT INTO reservas (org_id, cliente_nombre, cliente_tel, servicio_nombre, servicio_id, profesional_id, fecha_inicio, fecha_fin, estado, monto, origen)
SELECT
  '{{ $json.org_id }}',
  '{{ $json.tool_input.cliente_nombre || $json.pushName }}',
  '{{ $json.telefono }}',
  '{{ $json.tool_input.servicio_nombre }}',
  COALESCE((SELECT id FROM servicios WHERE org_id='{{ $json.org_id }}' AND nombre ILIKE '%' || '{{ $json.tool_input.servicio_nombre }}' || '%' LIMIT 1), 0),
  0,
  ('{{ $json.tool_input.fecha }}'::date + '{{ $json.tool_input.hora }}'::time),
  ('{{ $json.tool_input.fecha }}'::date + '{{ $json.tool_input.hora }}'::time) + interval '60 minutes',
  'confirmada',
  COALESCE((SELECT precio FROM servicios WHERE org_id='{{ $json.org_id }}' AND nombre ILIKE '%' || '{{ $json.tool_input.servicio_nombre }}' || '%' LIMIT 1), 0),
  'whatsapp'
WHERE (SELECT cnt FROM conflict_check) = 0
RETURNING id, fecha_inicio::text, estado""")

pg("PG Mis Citas", "6ac42e3f-f27a-4a2a-a338-4a38a930dbd9", [10176, 5264], "SELECT id, servicio_nombre, fecha_inicio::text, estado FROM reservas WHERE org_id='{{ $json.org_id }}' AND cliente_tel='{{ $json.telefono }}' AND fecha_inicio >= NOW() AND estado != 'cancelada' ORDER BY fecha_inicio LIMIT 5")

pg("PG Cancelar Cita", "e62c2de3-f2e5-4502-988d-717aed624835", [10176, 5424], "UPDATE reservas SET estado='cancelada', updated_at=NOW() WHERE id={{ $json.tool_input.cita_id }} AND org_id='{{ $json.org_id }}' AND cliente_tel='{{ $json.telefono }}' RETURNING id, servicio_nombre")

code("Merge Tool Result", "6f543740-3688-4aa9-bfa2-0470153442c4", [10416, 5216], r"""const ctx = $('Route Tool').first().json;
const toolResults = $input.all().map(i => i.json);
const tool = ctx.tool_use[0];

const resultText = JSON.stringify(toolResults);
const updatedMessages = [
  ...ctx.messages,
  { role: 'assistant', content: ctx.response_content },
  { role: 'user', content: [{ type: 'tool_result', tool_use_id: tool.id, content: resultText }]}
];

return [{ json: { ...ctx, messages: updatedMessages } }];""")

httpreq("Claude API 2", "eb09c9f7-1b45-4d48-899c-8b74cfc93f0d", [10656, 5216],
        "https://api.anthropic.com/v1/messages",
        [{"name": "x-api-key", "value": "={{ $json.anthropic_key || $env.ANTHROPIC_API_KEY }}"},
         {"name": "anthropic-version", "value": "2023-06-01"},
         {"name": "content-type", "value": "application/json"}],
        "={{ JSON.stringify({ model: 'claude-sonnet-4-20250514', max_tokens: 1024, system: $json.system, tools: $json.tools, messages: $json.messages }) }}")
nodes[-1]["parameters"]["options"] = {"timeout": 30000}

code("Extract Final", "504e1463-b876-487e-bc55-ecd86936686d", [10896, 5216], r"""const resp = $input.first().json;
const ctx = $('Build Prompt').first().json;
const content = resp.content || [];
const texto = content.filter(b=>b.type==='text').map(b=>b.text).join('');
return [{ json: { ...ctx, respuesta_final: texto } }];""")

code("Direct Final", "497c3cde-cecd-432b-a2e5-cbf0725279a7", [9696, 5376], r"""const ctx = $input.first().json;
return [{ json: { ...ctx, respuesta_final: ctx.respuesta_texto } }];""")

pg("PG Save Memoria", "866dfc23-8fbf-4e7e-b46e-553f9fc6475f", [11136, 5296], r"""INSERT INTO agent_memory (session_id, user_id, role, content)
VALUES
  ('{{ $json.session_id }}', '{{ $json.telefono }}', 'user', '{{ $json.texto.replace(/'/g, "''") }}'),
  ('{{ $json.session_id }}', '{{ $json.telefono }}', 'assistant', '{{ $json.respuesta_final.replace(/'/g, "''") }}')
ON CONFLICT DO NOTHING""")

httpreq("Send WA Response", "5c7a5d8d-7c56-4680-b71b-40e71a7fbc86", [11376, 5296],
        "={{ $json.evo_url }}/message/sendText/{{ $json.evo_instancia }}",
        [{"name": "apikey", "value": "={{ $json.evo_key }}"}, {"name": "Content-Type", "value": "application/json"}],
        "={{ JSON.stringify({ number: $json.telefono, textMessage: { text: $json.respuesta_final } }) }}")
nodes[-1]["parameters"]["options"] = {"timeout": 10000}

resp("Resp OK", "4e4fcc15-e5ff-4855-ae91-48e6b956d480", [11616, 5296], "={\"ok\":true}")

C("WH Evolution API", [[("Parse Mensaje", 0)]])
C("Parse Mensaje", [[("Skip o Procesar", 0)]])
C("Skip o Procesar", [[("Resp Skip", 0)], [("PG Get Org", 0)]])
C("PG Get Org", [[("PG Get Contexto", 0)]])
C("PG Get Contexto", [[("Build Prompt", 0)]])
C("Build Prompt", [[("Claude API", 0)]])
C("Claude API", [[("Check Tool Use", 0)]])
C("Check Tool Use", [[("Tool o Final", 0)]])
C("Tool o Final", [[("Route Tool", 0)], [("Direct Final", 0)]])
C("Route Tool", [[("SW Tools", 0)]])
C("SW Tools", [[("PG Disponibilidad", 0)], [("PG Crear Reserva", 0)], [("PG Mis Citas", 0)], [("PG Cancelar Cita", 0)]])
C("PG Disponibilidad", [[("Merge Tool Result", 0)]])
C("PG Crear Reserva", [[("Merge Tool Result", 0)]])
C("PG Mis Citas", [[("Merge Tool Result", 0)]])
C("PG Cancelar Cita", [[("Merge Tool Result", 0)]])
C("Merge Tool Result", [[("Claude API 2", 0)]])
C("Claude API 2", [[("Extract Final", 0)]])
C("Extract Final", [[("PG Save Memoria", 0)]])
C("Direct Final", [[("PG Save Memoria", 0)]])
C("PG Save Memoria", [[("Send WA Response", 0)]])
C("Send WA Response", [[("Resp OK", 0)]])

print("whatsapp agent section ok:", len(nodes), "nodes")

# ============================================================================
# RECORDATORIOS PROGRAMADOS 24h/2h — antes eran un toggle decorativo sin
# efecto; ahora un Schedule Trigger real que respeta esos toggles.
# ============================================================================
N(parameters={"rule": {"interval": [{"field": "minutes", "minutesInterval": 15}]}},
  id="a1a1a1a1-0001-4001-8001-100000000001", name="Cada 15 min", type="n8n-nodes-base.scheduleTrigger",
  typeVersion=1.2, position=[5648, 5680])

pg("PG Citas A Recordar", "a1a1a1a1-0002-4002-8002-100000000002", [5888, 5680], r"""SELECT r.id, r.org_id, r.cliente_nombre, r.cliente_tel, r.fecha_inicio::text, r.servicio_nombre,
       n.nombre AS negocio_nombre, c.datos->>'evo_url' AS evo_url, c.datos->>'evo_key' AS evo_key,
       c.datos->>'evo_instancia' AS evo_instancia, c.datos->>'msg_recordatorio' AS msg_recordatorio,
       (COALESCE((c.datos->>'notif_recordatorio_24h')::boolean, true)
         AND r.fecha_inicio BETWEEN now() + interval '23h45m' AND now() + interval '24h'
         AND r.recordatorio_24h_enviado IS NOT TRUE) AS es_24h,
       (COALESCE((c.datos->>'notif_recordatorio_2h')::boolean, true)
         AND r.fecha_inicio BETWEEN now() + interval '1h45m' AND now() + interval '2h'
         AND r.recordatorio_2h_enviado IS NOT TRUE) AS es_2h
FROM reservas r
JOIN negocios n ON n.org_id = r.org_id
LEFT JOIN configuracion c ON c.org_id = r.org_id
WHERE r.estado = 'confirmada'
  AND (
    (COALESCE((c.datos->>'notif_recordatorio_24h')::boolean, true) AND r.fecha_inicio BETWEEN now() + interval '23h45m' AND now() + interval '24h' AND r.recordatorio_24h_enviado IS NOT TRUE)
    OR
    (COALESCE((c.datos->>'notif_recordatorio_2h')::boolean, true) AND r.fecha_inicio BETWEEN now() + interval '1h45m' AND now() + interval '2h' AND r.recordatorio_2h_enviado IS NOT TRUE)
  )""")

code("Formatear Recordatorio", "a1a1a1a1-0003-4003-8003-100000000003", [6128, 5680], r"""const items = $input.all().map(i => i.json);
return items.map(r => {
  const plantilla = r.msg_recordatorio || 'Hola {nombre}, te recordamos tu cita. ¡Te esperamos! 🗓';
  const texto = plantilla.replace(/\{nombre\}/g, r.cliente_nombre || '').replace(/\{negocio\}/g, r.negocio_nombre || '');
  const numero = String(r.cliente_tel || '').replace(/[^0-9]/g, '');
  return { json: { reserva_id: r.id, org_id: r.org_id, tipo: r.es_24h ? '24h' : '2h', numero, texto, evo_url: r.evo_url, evo_key: r.evo_key, evo_instancia: r.evo_instancia } };
}).filter(i => i.json.numero && i.json.evo_url && i.json.evo_key);""")

httpreq("Enviar Recordatorio WA", "a1a1a1a1-0004-4004-8004-100000000004", [6368, 5680],
        "={{ $json.evo_url }}/message/sendText/{{ $json.evo_instancia }}",
        [{"name": "apikey", "value": "={{ $json.evo_key }}"}, {"name": "Content-Type", "value": "application/json"}],
        "={{ JSON.stringify({ number: $json.numero, text: $json.texto }) }}")
nodes[-1]["parameters"]["options"] = {"timeout": 10000}

pg("PG Marcar Enviado", "a1a1a1a1-0005-4005-8005-100000000005", [6608, 5680], r"""UPDATE reservas
SET recordatorio_24h_enviado = recordatorio_24h_enviado OR '{{ $json.tipo }}' = '24h',
    recordatorio_2h_enviado  = recordatorio_2h_enviado  OR '{{ $json.tipo }}' = '2h'
WHERE id = {{ $json.reserva_id }}""")

C("Cada 15 min", [[("PG Citas A Recordar", 0)]])
C("PG Citas A Recordar", [[("Formatear Recordatorio", 0)]])
C("Formatear Recordatorio", [[("Enviar Recordatorio WA", 0)]])
C("Enviar Recordatorio WA", [[("PG Marcar Enviado", 0)]])

print("recordatorios section ok:", len(nodes), "nodes")

# ============================================================================
# Validación + escritura del archivo final
# ============================================================================
names = [n["name"] for n in nodes]
ids = [n["id"] for n in nodes]
assert len(names) == len(set(names)), f"nombres duplicados: {[x for x in names if names.count(x)>1]}"
assert len(ids) == len(set(ids)), f"ids duplicados: {[x for x in ids if ids.count(x)>1]}"

name_set = set(names)
for src, val in connections.items():
    assert src in name_set, f"conexión desde nodo inexistente: {src}"
    for branch in val["main"]:
        for entry in branch:
            assert entry["node"] in name_set, f"conexión hacia nodo inexistente: {entry['node']} (desde {src})"

workflow = {
    "name": "AgendaOS - Backend (seguro)",
    "nodes": nodes,
    "connections": connections,
    "pinData": {},
    "meta": {"instanceId": "agendaos-secure-rebuild"}
}

with open("workflow-fixed.json", "w", encoding="utf-8") as f:
    json.dump(workflow, f, ensure_ascii=False, indent=2)

print("TOTAL:", len(nodes), "nodos ·", len(connections), "nodos con conexiones salientes")
print("archivo escrito: workflow-fixed.json")








