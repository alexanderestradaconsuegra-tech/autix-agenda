# Webhook de notificación MercadoPago — idempotencia + verificación real

No confiar nunca en el `status` que llega en el body de la notificación: hay que
consultar la API de MercadoPago con el `payment_id` antes de activar cualquier plan.

## Migración SQL (una vez)

```sql
CREATE TABLE IF NOT EXISTS pagos (
  id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id       UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
  provider     TEXT NOT NULL DEFAULT 'mercadopago',
  payment_id   TEXT NOT NULL,
  estado       TEXT NOT NULL,
  monto        NUMERIC(12,2) NOT NULL,
  moneda       TEXT NOT NULL DEFAULT 'CLP',
  raw          JSONB NOT NULL,
  procesado_at TIMESTAMPTZ,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (provider, payment_id)
);
```

## Nodo 1 — Code Node "Extraer payment_id"

```javascript
const body = $input.first().json.body ?? {};
const paymentId = String(body?.data?.id ?? body?.resource ?? '').split('/').pop();

if (!paymentId) return [{ json: { ok: true, skip: true, motivo: 'sin payment_id' } }];
if (body.type && body.type !== 'payment') return [{ json: { ok: true, skip: true, motivo: body.type } }];

return [{ json: { payment_id: paymentId } }];
```

## Nodo 2 — HTTP Request
`GET https://api.mercadopago.com/v1/payments/{{$json.payment_id}}`
Header `Authorization: Bearer {{$env.MP_PLATFORM_ACCESS_TOKEN}}` (el token de **tu** cuenta
MercadoPago para consultar el pago de la suscripción del plan, no el `mp_token` del tenant).

## Nodo 3 — Code Node "Decidir activación"

```javascript
const pago = $input.first().json; // respuesta real de la API de MP
const orgId = pago.external_reference; // debe venir seteado al crear la preferencia de pago
const estado = pago.status; // 'approved' | 'pending' | 'rejected' | ...

return [{ json: {
  org_id: orgId,
  payment_id: String(pago.id),
  estado,
  monto: pago.transaction_amount,
  moneda: pago.currency_id,
  raw: pago,
  activar_plan: estado === 'approved'
} }];
```

## Nodo 4 — Postgres "Insert idempotente"

```sql
INSERT INTO pagos (org_id, payment_id, estado, monto, moneda, raw, procesado_at)
VALUES ($1, $2, $3, $4, $5, $6::jsonb, now())
ON CONFLICT (provider, payment_id) DO UPDATE SET estado = EXCLUDED.estado
RETURNING id;
```
(Query Parameters: org_id, payment_id, estado, monto, moneda, JSON.stringify(raw) — nunca
concatenar valores en el SQL.)

## Nodo 5 — IF `{{$json.activar_plan}}` → Postgres "Activar plan"

```sql
UPDATE orgs SET plan = 'pro', plan_activado_at = now() WHERE id = $1;
```

Esto reemplaza cualquier lógica que hoy active el plan directamente al recibir el
`?pago=ok` del redirect del navegador — ese redirect es solo para la UX (mostrar el
toast), la activación real del plan **solo** ocurre aquí, verificada contra la API de MP.
