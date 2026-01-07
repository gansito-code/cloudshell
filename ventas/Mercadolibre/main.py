import os
import json
from datetime import datetime, timedelta, timezone

import functions_framework
import pytz
import requests
from google.cloud import bigquery
from google.cloud import secretmanager


# =========================
# CONFIG
# =========================

PROJECT_ID = os.environ.get("GCP_PROJECT") or os.environ.get("GOOGLE_CLOUD_PROJECT")
DATASET_ID = os.environ.get("BQ_DATASET", "ml_cs")
TABLE_ID = os.environ.get("BQ_TABLE", "ventas_vertical")
SELLER_ID = os.environ.get("ML_SELLER_ID")

TZ_NAME = os.environ.get("TZ", "America/Mexico_City")
MX_TZ = pytz.timezone(TZ_NAME)

# En lugar de leer directamente CLIENT_ID / CLIENT_SECRET,
# leemos NOMBRES de secretos desde env y luego los resolvemos con Secret Manager.
SM_REFRESH_SECRET = os.environ.get("SM_REFRESH_SECRET", "ML_REFRESH_TOKEN")
SM_CLIENT_ID = os.environ.get("SM_CLIENT_ID", "ML_CLIENT_ID")
SM_CLIENT_SECRET = os.environ.get("SM_CLIENT_SECRET", "ML_CLIENT_SECRET")


# =========================
# Secret Manager helpers
# =========================

def load_secret(secret_name: str) -> str:
    client = secretmanager.SecretManagerServiceClient()
    name = f"projects/{PROJECT_ID}/secrets/{secret_name}/versions/latest"
    resp = client.access_secret_version(request={"name": name})
    return resp.payload.data.decode("utf-8")


def save_secret(secret_name: str, value: str) -> None:
    client = secretmanager.SecretManagerServiceClient()
    parent = f"projects/{PROJECT_ID}/secrets/{secret_name}"
    client.add_secret_version(
        request={"parent": parent, "payload": {"data": value.encode("utf-8")}}
    )


def ml_refresh_token():
    """Renueva el access_token usando el refresh_token y credenciales guardadas en Secret Manager."""
    # Leemos valores REALES desde Secret Manager
    refresh_token = load_secret(SM_REFRESH_SECRET)
    client_id = load_secret(SM_CLIENT_ID)
    client_secret = load_secret(SM_CLIENT_SECRET)

    url = "https://api.mercadolibre.com/oauth/token"
    payload = {
        "grant_type": "refresh_token",
        "client_id": client_id,
        "client_secret": client_secret,
        "refresh_token": refresh_token,
    }
    headers = {"Content-Type": "application/x-www-form-urlencoded"}

    r = requests.post(url, data=payload, headers=headers)
    if r.status_code != 200:
        return None, f"Error refreshing ML token: {r.status_code} {r.text}"

    data = r.json()
    new_access = data["access_token"]
    new_refresh = data["refresh_token"]

    # Guardar nuevo refresh token
    save_secret(SM_REFRESH_SECRET, new_refresh)

    return new_access, None


# =========================
# Fechas: AYER MX → rango UTC
# =========================

def rango_ayer_local_a_utc():
    """
    Replica la lógica de Apps Script:

    var now       = new Date();
    var ayerLocal = new Date(now.getTime() - msPerDay);
    ayerLocal.setHours(0, 0, 0, 0);
    var startUTC  = new Date(ayerLocal).toISOString();
    var endUTC    = new Date(ayerLocal.getTime() + msPerDay - 1).toISOString();

    Aquí:
    - ayer_local: datetime "ayer 00:00:00" en America/Mexico_City
    - start_utc_str / end_utc_str: strings ISO con 'Z' (misma forma que toISOString)
    """
    ahora_local = datetime.now(MX_TZ)
    ayer_local = ahora_local - timedelta(days=1)

    # Ayer 00:00:00.000 en MX
    ayer_local = ayer_local.replace(hour=0, minute=0, second=0, microsecond=0)

    # Fin de día local: ayer 23:59:59.999
    fin_local = ayer_local + timedelta(days=1) - timedelta(milliseconds=1)

    # Convertir esos instantes a UTC y formatear EXACTO como toISOString() JS
    inicio_utc_dt = ayer_local.astimezone(timezone.utc)
    fin_utc_dt = fin_local.astimezone(timezone.utc)

    start_utc_str = inicio_utc_dt.strftime("%Y-%m-%dT%H:%M:%S.000Z")
    end_utc_str = fin_utc_dt.strftime("%Y-%m-%dT%H:%M:%S.000Z")

    # yyyy-MM-dd para filtro local posterior
    fecha_ayer_mx = ayer_local.strftime("%Y-%m-%d")

    print(f"RANGO Ayer MX → UTC: {fecha_ayer_mx}: {start_utc_str} → {end_utc_str}")

    return ayer_local, fecha_ayer_mx, start_utc_str, end_utc_str


# =========================
# Conversión de timestamp ML → MX
# =========================

def convertir_a_mx(fecha_iso: str) -> str | None:
    """
    Emula: Utilities.formatDate(new Date(ord.date_created),
    'America/Mexico_City', 'yyyy-MM-dd HH:mm:ss')
    """
    if not fecha_iso:
        return None

    norm = fecha_iso.replace("Z", "+00:00")

    try:
        dt = datetime.fromisoformat(norm)
    except Exception:
        dt = datetime.strptime(fecha_iso[:19], "%Y-%m-%dT%H:%M:%S")
        dt = dt.replace(tzinfo=timezone.utc)

    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)

    mx_dt = dt.astimezone(MX_TZ)
    return mx_dt.strftime("%Y-%m-%d %H:%M:%S")


# =========================
# Llamada a MercadoLibre
# =========================

def fetch_orders_for_utc_range(access_token: str, seller_id: str, start_utc: str, end_utc: str):
    """
    Igual que en Apps Script, pero ya recibe strings tipo toISOString():
    - start_utc / end_utc: "YYYY-MM-DDTHH:MM:SS.000Z"
    """
    print("Calling ML orders/search with range:", start_utc, "→", end_utc)

    all_orders = []
    offset = 0
    limit = 50

    while True:
        url = (
            "https://api.mercadolibre.com/orders/search"
            f"?seller={seller_id}"
            f"&order.date_created.from={start_utc}"
            f"&order.date_created.to={end_utc}"
            f"&offset={offset}&limit={limit}"
        )
        resp = requests.get(url, headers={"Authorization": f"Bearer {access_token}"})
        if resp.status_code != 200:
            raise RuntimeError(f"ML error: {resp.status_code} {resp.text}")

        data = resp.json()
        batch = data.get("results", [])
        all_orders.extend(batch)

        print(f"Batch offset={offset}: {len(batch)} órdenes")

        if len(batch) < limit:
            break

        offset += limit

    print("Total órdenes obtenidas (sin filtro local):", len(all_orders))
    return all_orders


# =========================
# Convertir órdenes → filas BQ (lineas de items)
# =========================

def build_rows_from_orders(orders, fecha_ayer_mx: str):
    """
    Genera filas por línea de item, pero SÓLO para órdenes cuya fecha local MX = fecha_ayer_mx.
    Igual que tu paso 4.1 (filtro por fecha local).
    """
    rows = []
    total_items = 0

    for order in orders:
        raw_created = order.get("date_created")
        fecha_mx_str = convertir_a_mx(raw_created)
        if not fecha_mx_str:
            continue

        # Filtro estricto por yyyy-MM-dd MX (como Apps Script)
        fecha_local = fecha_mx_str[:10]
        if fecha_local != fecha_ayer_mx:
            # equivalente al "⏭ Orden omitida" del log
            continue

        order_id = str(order.get("id"))

        for item in order.get("order_items", []):
            total_items += 1
            item_info = item.get("item", {})

            sku = item_info.get("seller_sku") or item.get("seller_custom_field") or item_info.get("id") or ""
            title = item_info.get("title") or ""
            price = float(item.get("unit_price") or 0.0)
            qty = int(item.get("quantity") or 0)

            rows.append(
                {
                    "id_orden": order_id,
                    "fecha_venta": fecha_mx_str,  # hora MX
                    "sku": str(sku),
                    "producto": title,
                    "precio": price,
                    "cantidad": qty,
                    "total": price * qty,
                }
            )

    print("Total líneas de items después de filtro local MX:", len(rows))
    rows.sort(key=lambda r: r["fecha_venta"])
    return rows


# =========================
# Insertar en BigQuery
# =========================

def insert_rows_bq(rows):
    client = bigquery.Client(project=PROJECT_ID)
    table_ref = f"{PROJECT_ID}.{DATASET_ID}.{TABLE_ID}"
    errors = client.insert_rows_json(table_ref, rows)
    return errors


# =========================
# CLOUD FUNCTION HTTP
# =========================

@functions_framework.http
def ingestar_ventas_ml(request):
    try:
        # 1) Token ML
        access_token, err = ml_refresh_token()
        if err:
            return json.dumps({"error": err}), 500, {"Content-Type": "application/json"}

        # 2) Rango AYER MX → UTC (forma Apps Script)
        ayer_local_dt, fecha_ayer_mx, start_utc, end_utc = rango_ayer_local_a_utc()

        # 3) Obtener órdenes desde ML
        orders = fetch_orders_for_utc_range(access_token, SELLER_ID, start_utc, end_utc)

        # 4) Construir filas sólo para órdenes cuya fecha local = ayer (MX)
        rows = build_rows_from_orders(orders, fecha_ayer_mx)

        # 5) Insertar en BigQuery
        errors = insert_rows_bq(rows)

        body = {
            "dataset": DATASET_ID,
            "table": TABLE_ID,
            "rows_ready": len(rows),
            "insert_errors": len(errors),
            "fecha_ayer_mx": fecha_ayer_mx,
            "range_utc": [start_utc, end_utc],
            "seller_id": SELLER_ID,
        }
        if errors:
            body["bq_errors"] = errors

        return json.dumps(body), 200, {"Content-Type": "application/json"}

    except Exception as e:
        print("ERROR en ingestar_ventas_ml:", e)
        return json.dumps({"error": str(e)}), 500, {"Content-Type": "application/json"}
