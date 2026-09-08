# Workflow programado — recordatorios reales de WhatsApp (24h / 2h)

Hoy los toggles "Recordatorio 24h antes" / "Recordatorio 2h antes" en Configuración
(`index.html`, sección "Notificaciones WhatsApp") se guardan como
`notif_recordatorio_24h` / `notif_recordatorio_2h` dentro de `agenda-configuracion`
(ya devuelto por `saveConfig()`/`loadConfig()` en el frontend), pero nada los lee. Este
workflow es lo que los vuelve funcionales de verdad, sin depender de que el dueño del
negocio haga clic manualmente en WhatsApp Web.

## Trigger
**Schedule Trigger**, cada 15 minutos.

## Nodo 1 — Postgres "Citas a recordar"

```sql
-- Citas confirmadas cuya hora de inicio cae dentro de la ventana [ahora+X, ahora+X+15min)
-- para 24h y para 2h, uniendo con la config de cada org para respetar los toggles y
-- evitando reenviar (columna recordatorio_24h_enviado / recordatorio_2h_enviado en reservas).
SELECT r.id, r.org_id, r.cliente_nombre, r.cliente_tel, r.fecha_inicio, r.servicio_nombre,
       o.nombre AS negocio_nombre, c.evo_url, c.evo_key, c.evo_instancia,
       c.msg_recordatorio,
       (c.notif_recordatorio_24h IS TRUE AND r.fecha_inicio BETWEEN now() + interval '23h45m' AND now() + interval '24h'
        AND r.recordatorio_24h_enviado IS NOT TRUE) AS es_24h,
       (c.notif_recordatorio_2h  IS TRUE AND r.fecha_inicio BETWEEN now() + interval '1h45m'  AND now() + interval '2h'
        AND r.recordatorio_2h_enviado  IS NOT TRUE) AS es_2h
FROM reservas r
JOIN orgs o           ON o.id = r.org_id
JOIN configuracion c  ON c.org_id = r.org_id
WHERE r.estado = 'confirmada'
  AND (
    (c.notif_recordatorio_24h IS TRUE AND r.fecha_inicio BETWEEN now() + interval '23h45m' AND now() + interval '24h' AND r.recordatorio_24h_enviado IS NOT TRUE)
    OR
    (c.notif_recordatorio_2h  IS TRUE AND r.fecha_inicio BETWEEN now() + interval '1h45m'  AND now() + interval '2h'  AND r.recordatorio_2h_enviado  IS NOT TRUE)
  );
```

(Ajusta nombres de tabla/columna a tu esquema real; el punto clave es filtrar por los
toggles de config y por una columna de "ya enviado" para no duplicar mensajes.)

## Nodo 2 — Code Node "Formatear mensaje + destino"

```javascript
const items = $input.all().map(i => i.json);
return items.map(r => {
  const plantilla = r.msg_recordatorio || 'Hola {nombre}, te recordamos tu cita. ¡Te esperamos! 🗓';
  const texto = plantilla
    .replace(/\{nombre\}/g, r.cliente_nombre || '')
    .replace(/\{negocio\}/g, r.negocio_nombre || '');
  const numero = String(r.cliente_tel || '').replace(/[^0-9]/g, '');
  return {
    json: {
      reserva_id: r.id, org_id: r.org_id, tipo: r.es_24h ? '24h' : '2h',
      numero, texto,
      evo_url: r.evo_url, evo_key: r.evo_key, evo_instancia: r.evo_instancia
    }
  };
}).filter(i => i.json.numero && i.json.evo_url && i.json.evo_key);
```

## Nodo 3 — HTTP Request (Evolution API) — por item

`POST {{$json.evo_url}}/message/sendText/{{$json.evo_instancia}}`
Header `apikey: {{$json.evo_key}}`
Body:
```json
{ "number": "{{$json.numero}}", "text": "{{$json.texto}}" }
```
Configurar reintentos: 3 intentos, backoff 5s/15s/45s (n8n: "Retry On Fail" + "Wait Between Tries").

## Nodo 4 — Postgres "Marcar enviado"

```sql
UPDATE reservas
SET recordatorio_24h_enviado = recordatorio_24h_enviado OR $2 = '24h',
    recordatorio_2h_enviado  = recordatorio_2h_enviado  OR $2 = '2h'
WHERE id = $1;
```
(Parámetros: `reserva_id`, `tipo`.)

## Columnas nuevas requeridas

```sql
ALTER TABLE reservas
  ADD COLUMN IF NOT EXISTS recordatorio_24h_enviado BOOLEAN NOT NULL DEFAULT FALSE,
  ADD COLUMN IF NOT EXISTS recordatorio_2h_enviado  BOOLEAN NOT NULL DEFAULT FALSE;
```
