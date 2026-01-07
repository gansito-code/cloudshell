# Deploy Test: 2026-01-05
import os
import json
from datetime import datetime, date, time, timedelta
from decimal import Decimal, ROUND_HALF_UP
from zoneinfo import ZoneInfo

import requests
import functions_framework
from google.cloud import bigquery


PROJECT_ID = os.environ.get("PROJECT_ID")
BQ_DATASET = os.environ.get("BQ_DATASET", "ml_cs")
BQ_TABLE = os.environ.get("BQ_TABLE", "ventas_shopify")
BQ_STAGE_TABLE = os.environ.get("BQ_STAGE_TABLE", "ventas_shopify_fix_stage")
TIMEZONE = os.environ.get("TIMEZONE", "America/Mexico_City")

SHOPIFY_ACCESS_TOKEN = os.environ["SHOPIFY_ACCESS_TOKEN"]
SHOPIFY_STORE_URL = os.environ["SHOPIFY_STORE_URL"]  # ej. "saludvida-mexico.myshopify.com"

BASE_URL = f"https://{SHOPIFY_STORE_URL}/admin/api/2024-01"
HEADERS = {
    "X-Shopify-Access-Token": SHOPIFY_ACCESS_TOKEN,
    "Content-Type": "application/json",
    "Accept": "application/json",
}

bq_client = bigquery.Client(project=PROJECT_ID)
tz_mx = ZoneInfo(TIMEZONE)
TWO_PLACES = Decimal("0.01")


# =========================
#   HELPERS GENERALES
# =========================

def _parse_iso_datetime(dt_str: str) -> datetime:
    """
    Convierte un ISO de Shopify a datetime con tz, luego lo pasa a MX.
    Shopify suele mandar '...Z' → UTC.
    """
    if dt_str.endswith("Z"):
        dt_str = dt_str.replace("Z", "+00:00")
    dt = datetime.fromisoformat(dt_str)
    return dt.astimezone(tz_mx)


def _get_target_date_from_request(request) -> date:
    """
    Si viene ?date=YYYY-MM-DD en la URL, usamos esa fecha en MX.
    Si no, usamos día anterior en MX.
    """
    date_param = request.args.get("date")
    now_mx = datetime.now(tz_mx)

    if date_param:
        return datetime.strptime(date_param, "%Y-%m-%d").date()

    return now_mx.date() - timedelta(days=1)


def _get_mx_day_range(target: date):
    """
    Devuelve (start_mx, end_mx) para el día completo en MX.
    """
    start_mx = datetime.combine(target, time(0, 0, 0), tzinfo=tz_mx)
    end_mx = datetime.combine(target, time(23, 59, 59), tzinfo=tz_mx)
    return start_mx, end_mx


def _get_window_days_from_request(request) -> int:
    """
    Para el fix: ?days=N, por defecto 30, máximo 90.
    """
    days_param = request.args.get("days")
    if not days_param:
        return 30
    try:
        d = int(days_param)
        return max(1, min(d, 90))
    except ValueError:
        return 30


def _get_mx_range_for_last_days(days: int):
    """
    Ventana de últimos 'days' días completos en MX (incluyendo hoy).
    """
    now_mx = datetime.now(tz_mx)
    end_date = now_mx.date()
    start_date = end_date - timedelta(days=days - 1)

    start_mx = datetime.combine(start_date, time(0, 0, 0), tzinfo=tz_mx)
    end_mx = datetime.combine(end_date, time(23, 59, 59), tzinfo=tz_mx)
    return start_mx, end_mx


def fetch_shopify_orders(start_mx: datetime, end_mx: datetime):
    """
    Trae todas las órdenes en el rango [start_mx, end_mx] usando created_at_min/max
    en horaria MX con offset, financial_status=paid, paginando por Link header.
    """
    orders = []

    params = {
        "status": "any",
        "financial_status": "paid",
        "limit": 250,
        "created_at_min": start_mx.isoformat(),
        "created_at_max": end_mx.isoformat(),
    }

    url = f"{BASE_URL}/orders.json"

    while url:
        resp = requests.get(url, headers=HEADERS, params=params)
        resp.raise_for_status()
        data = resp.json()

        batch = data.get("orders", [])
        orders.extend(batch)

        # Para siguientes páginas, Shopify usa Link header con page_info
        next_link = resp.links.get("next", {}).get("url")
        if next_link:
            url = next_link
            params = None  # en cursors no se reenvían los params iniciales
        else:
            url = None

    return orders


def build_rows_from_orders(orders):
    """
    Construye la lista de filas para BigQuery a partir de las órdenes de Shopify.
    Una fila por line_item.
    """
    rows = []
    ingestion_ts = datetime.utcnow()

    for order in orders:
        order_id = str(order.get("id"))
        order_name = order.get("name")
        created_at_str = order.get("created_at")

        if not created_at_str:
            continue

        created_at_mx = _parse_iso_datetime(created_at_str)

        financial_status = order.get("financial_status")
        fulfillment_status = order.get("fulfillment_status")  # a nivel orden
        currency = order.get("currency")
        source_name = order.get("source_name")

        customer = order.get("customer") or {}
        customer_id = customer.get("id")
        customer_email = customer.get("email")

        line_items = order.get("line_items", [])

        for item in line_items:
            line_item_id = str(item.get("id"))
            sku = item.get("sku")
            product_name = item.get("name")
            quantity = item.get("quantity") or 0

            # Monetarios como Decimal
            price_str = item.get("price") or "0"
            unit_price = Decimal(price_str)

            # Descuentos por línea
            discount_allocations = item.get("discount_allocations", [])
            line_discount = sum(
                (Decimal(d.get("amount") or "0") for d in discount_allocations),
                start=Decimal("0"),
            )

            # Impuestos por línea
            tax_lines = item.get("tax_lines", [])
            line_tax = sum(
                (Decimal(t.get("price") or "0") for t in tax_lines),
                start=Decimal("0"),
            )

            # Totales línea = precio_unit * qty - desc + impuestos
            base_total = (unit_price * Decimal(quantity)).quantize(
                TWO_PLACES, rounding=ROUND_HALF_UP
            )
            line_discount = line_discount.quantize(TWO_PLACES, rounding=ROUND_HALF_UP)
            line_tax = line_tax.quantize(TWO_PLACES, rounding=ROUND_HALF_UP)

            line_total = (base_total - line_discount + line_tax).quantize(
                TWO_PLACES, rounding=ROUND_HALF_UP
            )

            row = {
                "order_id": order_id,
                "order_name": order_name,
                "purchase_date_mx": created_at_mx,
                "line_item_id": line_item_id,
                "seller_sku": sku,
                "product_name": product_name,
                "quantity": int(quantity),
                "unit_price_amount": unit_price.quantize(
                    TWO_PLACES, rounding=ROUND_HALF_UP
                ),
                "line_discount_amount": line_discount,
                "line_tax_amount": line_tax,
                "line_total_amount": line_total,
                "currency": currency,
                "financial_status": financial_status,
                "fulfillment_status": fulfillment_status,
                "source_name": source_name,
                "customer_id": str(customer_id) if customer_id is not None else None,
                "customer_email": customer_email,
                "ingestion_timestamp": ingestion_ts,
                "source_system": "shopify",
            }

            rows.append(row)

    return rows


def _convert_rows_for_bq(rows):
    """
    Convierte datetime/Decimal a strings compatibles con JSON/BigQuery.
    Asumimos que purchase_date_mx e ingestion_timestamp son TIMESTAMP en la tabla.
    """
    safe_rows = []

    for r in rows:
        row = dict(r)

        val = row.get("purchase_date_mx")
        if isinstance(val, datetime):
            # TIMESTAMP en MX como ISO (BigQuery lo interpreta bien)
            row["purchase_date_mx"] = val.isoformat()

        val = row.get("ingestion_timestamp")
        if isinstance(val, datetime):
            row["ingestion_timestamp"] = val.isoformat()

        for key in (
            "unit_price_amount",
            "line_discount_amount",
            "line_tax_amount",
            "line_total_amount",
        ):
            val = row.get(key)
            if isinstance(val, Decimal):
                row[key] = str(val)

        safe_rows.append(row)

    return safe_rows


# ======================================
#   INGESTA DIARIA (INSERT SIN MERGE)
# ======================================

def insert_rows_to_bigquery(rows):
    """
    Inserción masiva (ingesta diaria) sin MERGE.
    """
    if not rows:
        return 0, []

    table_id = f"{PROJECT_ID}.{BQ_DATASET}.{BQ_TABLE}"
    safe_rows = _convert_rows_for_bq(rows)

    errors = bq_client.insert_rows_json(table_id, safe_rows)
    return len(rows), errors


@functions_framework.http
def main(request):
    """
    Cloud Function HTTP (Gen2) para ingestar ventas Shopify (día anterior MX por defecto).
    Ahora usa staging + MERGE para que sea idempotente.
    Optional query param: ?date=YYYY-MM-DD para forzar un día concreto (MX).
    """
    target_date = _get_target_date_from_request(request)
    start_mx, end_mx = _get_mx_day_range(target_date)

    try:
        # Reutilizamos la misma lógica que para el fix,
        # pero solo para el rango de ese día.
        orders, rows = build_rows_for_range(start_mx, end_mx)

        # Cargar en tabla de staging (se sobreescribe)
        rows_stage = load_stage_table(rows)

        # MERGE único a la tabla principal
        merge_info = run_merge()

        resp = {
            "dataset": BQ_DATASET,
            "table": BQ_TABLE,
            "stage_table": BQ_STAGE_TABLE,
            "rows_stage": rows_stage,
            "range_mx": [start_mx.isoformat(), end_mx.isoformat()],
            "target_date_mx": str(target_date),
            "orders_count": len(orders),
            "merge": merge_info,
        }

        return (json.dumps(resp, default=str), 200, {"Content-Type": "application/json"})

    except Exception as e:
        resp = {
            "error": str(e),
            "target_date_mx": str(target_date),
        }
        return (json.dumps(resp, default=str), 500, {"Content-Type": "application/json"})


# ======================================
#   FIX CON STAGING + MERGE ÚNICO
# ======================================

def build_rows_for_range(start_mx: datetime, end_mx: datetime):
    """
    Reutiliza la lógica existente para traer órdenes y convertirlas a filas
    para BigQuery (mismos campos que la ingesta diaria).
    """
    orders = fetch_shopify_orders(start_mx, end_mx)
    rows = build_rows_from_orders(orders)
    return orders, rows


def load_stage_table(rows):
    """
    Carga rows en la tabla staging con WRITE_TRUNCATE.
    """
    table_id = f"{PROJECT_ID}.{BQ_DATASET}.{BQ_STAGE_TABLE}"

    if not rows:
        return 0

    safe_rows = _convert_rows_for_bq(rows)

    job_config = bigquery.LoadJobConfig(
        write_disposition=bigquery.WriteDisposition.WRITE_TRUNCATE
    )

    load_job = bq_client.load_table_from_json(
        safe_rows, table_id, job_config=job_config
    )
    load_job.result()  # espera a que termine

    table = bq_client.get_table(table_id)
    return table.num_rows


def run_merge():
    """
    MERGE desde staging a tabla principal.
    Clave: (order_id, line_item_id).
    Se castea desde la tabla staging para asegurar tipos correctos.
    """
    main_table = f"`{PROJECT_ID}.{BQ_DATASET}.{BQ_TABLE}`"
    stage_table = f"`{PROJECT_ID}.{BQ_DATASET}.{BQ_STAGE_TABLE}`"

    merge_sql = f"""
    MERGE {main_table} AS t
    USING (
      SELECT
        CAST(order_id AS STRING)       AS order_id,
        CAST(order_name AS STRING)     AS order_name,
        -- purchase_date_mx ya es TIMESTAMP en la tabla staging
        purchase_date_mx               AS purchase_date_mx,
        CAST(line_item_id AS STRING)   AS line_item_id,
        CAST(seller_sku AS STRING)     AS seller_sku,
        CAST(product_name AS STRING)   AS product_name,
        CAST(quantity AS INT64)        AS quantity,
        CAST(unit_price_amount AS NUMERIC)    AS unit_price_amount,
        CAST(line_discount_amount AS NUMERIC) AS line_discount_amount,
        CAST(line_tax_amount AS NUMERIC)      AS line_tax_amount,
        CAST(line_total_amount AS NUMERIC)    AS line_total_amount,
        CAST(currency AS STRING)       AS currency,
        CAST(financial_status AS STRING)  AS financial_status,
        CAST(fulfillment_status AS STRING) AS fulfillment_status,
        CAST(source_name AS STRING)    AS source_name,
        CAST(customer_id AS STRING)    AS customer_id,
        customer_email,
        ingestion_timestamp,
        source_system
      FROM {stage_table}
    ) AS s
    ON t.order_id = s.order_id
       AND t.line_item_id = s.line_item_id
    WHEN MATCHED THEN
      UPDATE SET
        t.order_name           = s.order_name,
        t.purchase_date_mx     = s.purchase_date_mx,
        t.seller_sku           = s.seller_sku,
        t.product_name         = s.product_name,
        t.quantity             = s.quantity,
        t.unit_price_amount    = s.unit_price_amount,
        t.line_discount_amount = s.line_discount_amount,
        t.line_tax_amount      = s.line_tax_amount,
        t.line_total_amount    = s.line_total_amount,
        t.currency             = s.currency,
        t.financial_status     = s.financial_status,
        t.fulfillment_status   = s.fulfillment_status,
        t.source_name          = s.source_name,
        t.customer_id          = s.customer_id,
        t.customer_email       = s.customer_email,
        t.ingestion_timestamp  = s.ingestion_timestamp,
        t.source_system        = s.source_system
    WHEN NOT MATCHED THEN
      INSERT (
        order_id,
        order_name,
        purchase_date_mx,
        line_item_id,
        seller_sku,
        product_name,
        quantity,
        unit_price_amount,
        line_discount_amount,
        line_tax_amount,
        line_total_amount,
        currency,
        financial_status,
        fulfillment_status,
        source_name,
        customer_id,
        customer_email,
        ingestion_timestamp,
        source_system
      )
      VALUES (
        s.order_id,
        s.order_name,
        s.purchase_date_mx,
        s.line_item_id,
        s.seller_sku,
        s.product_name,
        s.quantity,
        s.unit_price_amount,
        s.line_discount_amount,
        s.line_tax_amount,
        s.line_total_amount,
        s.currency,
        s.financial_status,
        s.fulfillment_status,
        s.source_name,
        s.customer_id,
        s.customer_email,
        s.ingestion_timestamp,
        s.source_system
      )
    """

    job = bq_client.query(merge_sql)
    job.result()  # esperamos a que termine
    return {"merge_job_id": job.job_id}



@functions_framework.http
def fix_shopify(request):
    """
    Entry point de Cloud Function para “fix” Shopify.
    Revisa últimos N días (por defecto 30) y hace:
      1) Carga en tabla staging
      2) MERGE único a ventas_shopify
    """
    days = _get_window_days_from_request(request)
    start_mx, end_mx = _get_mx_range_for_last_days(days)

    try:
        orders, rows = build_rows_for_range(start_mx, end_mx)
        stage_rows = load_stage_table(rows)
        merge_info = run_merge()

        resp = {
            "dataset": BQ_DATASET,
            "table": BQ_TABLE,
            "stage_table": BQ_STAGE_TABLE,
            "window_days": days,
            "range_mx": [start_mx.isoformat(), end_mx.isoformat()],
            "orders_count": len(orders),
            "rows_stage": stage_rows,
            "merge": merge_info,
        }
        return (
            json.dumps(resp, default=str),
            200,
            {"Content-Type": "application/json"},
        )
    except Exception as e:
        resp = {
            "error": str(e),
            "window_days": days,
            "range_mx": [start_mx.isoformat(), end_mx.isoformat()],
        }
        return (
            json.dumps(resp, default=str),
            500,
            {"Content-Type": "application/json"},
        )
