import os
import json
import time
import logging
import hmac
import hashlib
import urllib.parse
from datetime import datetime, timedelta
from typing import Dict, Tuple, Any

import pytz
import requests
import functions_framework
from google.cloud import secretmanager
from google.cloud import bigquery


# =========================
# CONFIGURACIÓN BÁSICA
# =========================

MX_TZ = pytz.timezone("America/Mexico_City")
UTC = pytz.utc

PROJECT_ID = (
    os.environ.get("GCP_PROJECT")
    or os.environ.get("GOOGLE_CLOUD_PROJECT")
    or os.environ.get("PROJECT_ID")
)

BQ_DATASET = os.environ.get("BQ_DATASET", "ml_cs")
BQ_TABLE = os.environ.get("BQ_TABLE", "ventas_amazon")

AMZ_BASE_URL = os.environ.get(
    "AMZ_BASE_URL", "https://sellingpartnerapi-na.amazon.com"
)
AMZ_REGION = os.environ.get("AMZ_REGION", "us-east-1")
AMZ_SERVICE = os.environ.get("AMZ_SERVICE", "execute-api")
AMZ_MARKETPLACE_ID = os.environ.get("AMZ_MARKETPLACE_ID", "A1AM78C64UM0Y8")

# Nombres de secretos en Secret Manager
SECRET_AMZ_REFRESH_TOKEN = os.environ.get("AMZ_REFRESH_TOKEN_SECRET", "AMZ_REFRESH_TOKEN")
SECRET_AMZ_CLIENT_ID = os.environ.get("AMZ_CLIENT_ID_SECRET", "AMZ_CLIENT_ID")
SECRET_AMZ_CLIENT_SECRET = os.environ.get("AMZ_CLIENT_SECRET_SECRET", "AMZ_CLIENT_SECRET")
SECRET_AWS_ACCESS_KEY = os.environ.get("AWS_ACCESS_KEY_SECRET", "AWS_ACCESS_KEY")
SECRET_AWS_SECRET_KEY = os.environ.get("AWS_SECRET_KEY_SECRET", "AWS_SECRET_KEY")

secret_client = secretmanager.SecretManagerServiceClient()
bq_client = bigquery.Client()


# =========================
# UTILIDADES
# =========================

def get_secret(secret_name: str) -> str:
    """Lee un secreto de Secret Manager (versión latest)."""
    name = f"projects/{PROJECT_ID}/secrets/{secret_name}/versions/latest"
    response = secret_client.access_secret_version(request={"name": name})
    return response.payload.data.decode("utf-8")


def sha256_hex(text: str) -> str:
    """Hash SHA256 en hexadecimal."""
    return hashlib.sha256((text or "").encode("utf-8")).hexdigest()


def generate_aws_signature(method: str, endpoint: str, payload: str,
                           access_key: str, secret_key: str,
                           region: str, service: str) -> str:
    """
    Genera firma AWS Signature V4:
    - canonicalRequest sin query string
    - solo header 'host' en SignedHeaders
    """
    logging.info("Generando firma AWS para %s %s", method, endpoint)

    now_utc = datetime.utcnow()
    amz_datetime = now_utc.strftime("%Y%m%dT%H%M%SZ")
    date_stamp = amz_datetime[:8]

    payload_hash = sha256_hex(payload or "")

    host = AMZ_BASE_URL.replace("https://", "").replace("http://", "")
    canonical_request = "\n".join([
        method,
        endpoint,
        "",                     # query string vacío
        f"host:{host}",
        "",
        "host",                 # SignedHeaders
        payload_hash,
    ])

    credential_scope = f"{date_stamp}/{region}/{service}/aws4_request"
    string_to_sign = "\n".join([
        "AWS4-HMAC-SHA256",
        amz_datetime,
        credential_scope,
        sha256_hex(canonical_request),
    ])

    def sign(key: bytes, msg: str) -> bytes:
        return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()

    k_date = sign(("AWS4" + secret_key).encode("utf-8"), date_stamp)
    k_region = sign(k_date, region)
    k_service = sign(k_region, service)
    k_signing = sign(k_service, "aws4_request")
    signature = hmac.new(k_signing, string_to_sign.encode("utf-8"), hashlib.sha256).hexdigest()

    authorization = (
        f"AWS4-HMAC-SHA256 "
        f"Credential={access_key}/{credential_scope}, "
        f"SignedHeaders=host, "
        f"Signature={signature}"
    )
    return authorization


def get_access_token() -> str:
    """Obtiene access_token de Amazon usando el refresh_token."""
    logging.info("Obteniendo access_token de Amazon...")

    refresh_token = get_secret(SECRET_AMZ_REFRESH_TOKEN)
    client_id = get_secret(SECRET_AMZ_CLIENT_ID)
    client_secret = get_secret(SECRET_AMZ_CLIENT_SECRET)

    url = "https://api.amazon.com/auth/o2/token"
    payload = {
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
        "client_id": client_id,
        "client_secret": client_secret,
        "scope": "sellingpartnerapi::migration sellingpartnerapi::notifications sellingpartnerapi::finance",
    }

    resp = requests.post(url, data=payload, timeout=30)
    logging.info("Respuesta access_token: %s", resp.status_code)

    if resp.status_code != 200:
        logging.error("Error en getAccessToken: %s", resp.text)
        raise RuntimeError(f"Error en getAccessToken: {resp.text}")

    data = resp.json()
    access_token = data.get("access_token")
    if not access_token:
        raise RuntimeError("No se recibió access_token en la respuesta de Amazon.")
    logging.info("access_token obtenido correctamente.")
    return access_token


def sp_api_request(method: str, endpoint: str, access_token: str,
                   query_params: dict | None = None,
                   payload: str = "",
                   max_retries: int = 10) -> dict:
    """
    Llamada genérica a SP-API:
    - Firma AWS SigV4
    - Manejo de QuotaExceeded con espera y reintento
    """
    aws_access_key = get_secret(SECRET_AWS_ACCESS_KEY)
    aws_secret_key = get_secret(SECRET_AWS_SECRET_KEY)

    url = AMZ_BASE_URL + endpoint
    if query_params:
        qs = urllib.parse.urlencode(query_params, doseq=True)
        url = f"{url}?{qs}"

    signature = generate_aws_signature(
        method=method,
        endpoint=endpoint,
        payload=payload,
        access_key=aws_access_key,
        secret_key=aws_secret_key,
        region=AMZ_REGION,
        service=AMZ_SERVICE,
    )

    headers = {
        "Authorization": signature,
        "x-amz-access-token": access_token,
        "Content-Type": "application/json",
    }

    for attempt in range(1, max_retries + 1):
        resp = requests.request(method, url, headers=headers, data=payload or None, timeout=60)

        if resp.status_code == 200:
            return resp.json()

        code = None
        try:
            data = resp.json()
            errors = data.get("errors") or []
            if errors:
                code = errors[0].get("code")
        except Exception:
            data = None

        if code == "QuotaExceeded":
            wait_s = 15  # Reducido de 50s a 15s (Finances API recupera 0.5/s)
            logging.warning(
                "QuotaExceeded en SP-API (%s %s). Intento %d/%d. Esperando %d s...",
                method, endpoint, attempt, max_retries, wait_s,
            )
            time.sleep(wait_s)
            continue

        logging.error(
            "Error en SP-API (%s %s): status=%s body=%s",
            method, endpoint, resp.status_code, resp.text,
        )
        raise RuntimeError(f"Error SP-API {method} {endpoint}: {resp.status_code} {resp.text}")

    raise RuntimeError(f"Se excedieron los reintentos para SP-API {method} {endpoint}")


def get_yesterday_bounds_utc_for_mexico() -> Tuple[str, str, str]:
    """
    Calcula el día de AYER en horario America/Mexico_City y devuelve:
    - start_utc_iso (CreatedAfter)
    - end_utc_iso   (CreatedBefore)
    - date_mx_str   (YYYY-MM-DD en MX)
    """
    now_mx = datetime.now(MX_TZ)
    yesterday_mx = (now_mx - timedelta(days=1)).date()

    start_mx = MX_TZ.localize(datetime(
        year=yesterday_mx.year,
        month=yesterday_mx.month,
        day=yesterday_mx.day,
        hour=0, minute=0, second=0,
    ))
    end_mx = MX_TZ.localize(datetime(
        year=yesterday_mx.year,
        month=yesterday_mx.month,
        day=yesterday_mx.day,
        hour=23, minute=59, second=59,
    ))

    start_utc = start_mx.astimezone(UTC)
    end_utc = end_mx.astimezone(UTC)

    start_iso = start_utc.strftime("%Y-%m-%dT%H:%M:%SZ")
    end_iso = end_utc.strftime("%Y-%m-%dT%H:%M:%SZ")
    date_mx_str = yesterday_mx.strftime("%Y-%m-%d")

    logging.info(
        "Rango de AYER MX (CreatedAt): %s a %s (UTC). Día MX: %s",
        start_iso, end_iso, date_mx_str,
    )
    return start_iso, end_iso, date_mx_str


def fetch_orders_for_yesterday(access_token: str) -> list[dict]:
    """
    Obtiene órdenes del día de ayer (MX) usando CreatedAfter/Before
    y maneja paginación con NextToken.
    Luego aplica filtro adicional por PurchaseDate en MX.
    """
    created_after, created_before, date_mx_str = get_yesterday_bounds_utc_for_mexico()

    endpoint = "/orders/v0/orders"
    base_query_params = {
        "MarketplaceIds": AMZ_MARKETPLACE_ID,
        "CreatedAfter": created_after,
        "CreatedBefore": created_before,
    }

    all_orders: list[dict] = []
    next_token = None

    while True:
        params = dict(base_query_params)
        if next_token:
            params["NextToken"] = next_token

        data = sp_api_request("GET", endpoint, access_token, query_params=params)

        payload = data.get("payload") or {}
        orders = payload.get("Orders") or []
        all_orders.extend(orders)

        next_token = payload.get("NextToken")
        logging.info("NextToken: %s", next_token)
        if not next_token:
            break

        time.sleep(2)

    # Filtro adicional por PurchaseDate en MX
    filtered = []
    for order in all_orders:
        purchase_iso = order.get("PurchaseDate")
        if not purchase_iso:
            continue
        try:
            if purchase_iso.endswith("Z"):
                dt_utc = datetime.fromisoformat(purchase_iso.replace("Z", "+00:00"))
            else:
                dt_utc = datetime.fromisoformat(purchase_iso)
            dt_utc = dt_utc.astimezone(UTC)
            dt_mx = dt_utc.astimezone(MX_TZ)
            if dt_mx.strftime("%Y-%m-%d") == date_mx_str:
                filtered.append(order)
        except Exception:
            continue

    logging.info(
        "Órdenes obtenidas: %d, órdenes para AYER MX (PurchaseDate): %d",
        len(all_orders), len(filtered),
    )
    return filtered


def fetch_order_items(order_id: str, access_token: str) -> list[dict]:
    """Obtiene items de una orden."""
    endpoint = f"/orders/v0/orders/{order_id}/orderItems"
    data = sp_api_request("GET", endpoint, access_token)
    payload = data.get("payload") or {}
    items = payload.get("OrderItems") or []
    logging.info("Orden %s contiene %d item(s).", order_id, len(items))
    return items


def convert_iso_to_mx_and_utc(purchase_iso: str) -> Tuple[str | None, str | None]:
    """Convierte PurchaseDate ISO a:
    - purchase_utc_iso
    - purchase_mx_iso (YYYY-MM-DD HH:MM:SS)
    """
    if not purchase_iso:
        return None, None

    if purchase_iso.endswith("Z"):
        dt_utc = datetime.fromisoformat(purchase_iso.replace("Z", "+00:00"))
    else:
        dt_utc = datetime.fromisoformat(purchase_iso)

    dt_utc = dt_utc.astimezone(UTC)
    dt_mx = dt_utc.astimezone(MX_TZ)

    utc_iso = dt_utc.strftime("%Y-%m-%dT%H:%M:%SZ")
    mx_iso = dt_mx.strftime("%Y-%m-%d %H:%M:%S")
    return utc_iso, mx_iso


def build_rows_from_orders(orders: list[dict], access_token: str) -> list[dict]:
    """
    Construye filas para BigQuery con los campos base + shipping/promos/gift wrap.
    """
    rows: list[dict] = []

    for order in orders:
        order_id = order.get("AmazonOrderId")
        merchant_order_id = order.get("MerchantOrderId")
        purchase_date_iso = order.get("PurchaseDate")
        last_update_iso = order.get("LastUpdateDate")

        # PurchaseDate en MX
        purchase_date_mx = None
        if purchase_date_iso:
            if purchase_date_iso.endswith("Z"):
                dt_utc = datetime.fromisoformat(purchase_date_iso.replace("Z", "+00:00"))
            else:
                dt_utc = datetime.fromisoformat(purchase_date_iso)
            dt_mx = dt_utc.astimezone(MX_TZ)
            purchase_date_mx = dt_mx.strftime("%Y-%m-%d %H:%M:%S")

        # LastUpdateDate en MX
        last_update_mx = None
        if last_update_iso:
            if last_update_iso.endswith("Z"):
                dt_utc2 = datetime.fromisoformat(last_update_iso.replace("Z", "+00:00"))
            else:
                dt_utc2 = datetime.fromisoformat(last_update_iso)
            dt_mx2 = dt_utc2.astimezone(MX_TZ)
            last_update_mx = dt_mx2.strftime("%Y-%m-%d %H:%M:%S")

        items = fetch_order_items(order_id, access_token)

        for item in items:
            sku = item.get("SellerSKU")
            asin = item.get("ASIN")
            title = item.get("Title")
            qty = item.get("QuantityOrdered", 0)

            # Precios base e impuestos
            item_price = item.get("ItemPrice") or {}
            item_tax = item.get("ItemTax") or {}

            base_amount = round(float(item_price.get("Amount", 0) or 0), 2)
            tax_amount = round(float(item_tax.get("Amount", 0) or 0), 2)
            total_amount = round(base_amount + tax_amount, 2)
            currency = item_price.get("CurrencyCode")

            # Nuevos campos: Shipping / Promos / Gift wrap
            shipping_price = item.get("ShippingPrice") or {}
            shipping_tax = item.get("ShippingTax") or {}
            promotion_discount = item.get("PromotionDiscount") or {}
            shipping_discount = item.get("ShippingDiscount") or {}
            gift_wrap_price = item.get("GiftWrapPrice") or {}
            gift_wrap_tax = item.get("GiftWrapTax") or {}

            shipping_price_amount = round(float(shipping_price.get("Amount", 0) or 0), 2)
            shipping_tax_amount = round(float(shipping_tax.get("Amount", 0) or 0), 2)
            item_promo_amount = round(float(promotion_discount.get("Amount", 0) or 0), 2)
            shipping_promo_amount = round(float(shipping_discount.get("Amount", 0) or 0), 2)
            gift_wrap_price_amount = round(float(gift_wrap_price.get("Amount", 0) or 0), 2)
            gift_wrap_tax_amount = round(float(gift_wrap_tax.get("Amount", 0) or 0), 2)

            # Cálculo de Gross Revenue (Requerido por el Dashboard)
            # Item Price (Base + Tax) + Shipping - Promos
            gross_revenue = round(total_amount + shipping_price_amount - item_promo_amount - shipping_promo_amount, 2)

            row = {
                "order_id": order_id,
                "merchant_order_id": merchant_order_id,
                "purchase_date_mx": purchase_date_mx,
                "last_update_mx": last_update_mx,
                "seller_sku": sku,
                "asin": asin,
                "title": title,
                "quantity": qty,
                "item_price_amount": base_amount,
                "item_price_currency": currency,
                "item_tax_amount": tax_amount,
                "item_total_amount": total_amount,
                "gross_revenue_amount": gross_revenue,
                "fulfillment_channel": order.get("FulfillmentChannel"),
                "order_status": order.get("OrderStatus"),
                "shipment_service_level": order.get("ShipmentServiceLevelCategory"),

                "shipping_price_amount": shipping_price_amount,
                "shipping_tax_amount": shipping_tax_amount,
                "item_promotion_discount_amount": item_promo_amount,
                "shipping_promotion_discount_amount": shipping_promo_amount,
                "gift_wrap_price_amount": gift_wrap_price_amount,
                "gift_wrap_tax_amount": gift_wrap_tax_amount,
            }

            rows.append(row)

    logging.info("Filas construidas para BigQuery (con campos extendidos): %d", len(rows))
    return rows


def insert_rows_bigquery(rows: list[dict]) -> list:
    """Inserta filas en BigQuery usando insert_rows_json."""
    if not rows:
        logging.info("No hay filas para insertar en BigQuery.")
        return []

    table_id = f"{PROJECT_ID}.{BQ_DATASET}.{BQ_TABLE}"
    errors = bq_client.insert_rows_json(table_id, rows)
    if errors:
        logging.error("Errores al insertar en BigQuery: %s", errors)
    else:
        logging.info("Inserción en BigQuery correcta: %d filas.", len(rows))
    return errors


# =========================
# FIX: MONTOS 0
# =========================

@functions_framework.http
def fix_ventas_amazon_zero(request):
    """
    FIX MAESTRO V2 (Amazon Zero):
    - Auditor de órdenes con venta 0 o NULL.
    - Usa la Orders API (igual que la ingesta) para verificar datos finales.
    - Solo actualiza campos de ingresos y estado (NO toca fees ni taxes).
    - Borra órdenes que siguen en 0 tras >30 días.
    """
    logging.info("🚀 Iniciando Auditoría Amazon Zero...")
    table_ref = f"`{PROJECT_ID}.{BQ_DATASET}.{BQ_TABLE}`"

    try:
        # --- PARÁMETROS ---
        order_id_param = request.args.get("order_id")
        target_date_str = request.args.get("target_date")
        start_date_str = request.args.get("start_date")
        end_date_str = request.args.get("end_date")
        days_param = request.args.get("days")
        days_ago_start = request.args.get("days_ago_start")
        days_ago_end = request.args.get("days_ago_end")
        
        # Default True: solo busca ceros. Si es false, audita todo el rango.
        only_missing = request.args.get("only_missing") != "false"
        
        window_days = int(days_param) if days_param else 60
        if window_days < 1: window_days = 1
        if window_days > 180: window_days = 180

        query_parameters = []
        extra_filter = ""
        if only_missing:
            logging.info("🚀 MODO AUDITORÍA ZERO: Buscando órdenes con valores de precio/impuesto en 0.")
            extra_filter = """
              AND (
                item_total_amount IS NULL OR item_total_amount = 0 OR
                item_price_amount IS NULL OR item_price_amount = 0 OR
                gross_revenue_amount IS NULL OR gross_revenue_amount = 0
              )
            """
        else:
            logging.info("🐢 MODO AUDITORÍA TOTAL: Revisando todas las órdenes.")

        # --- CONSTRUCCIÓN DEL QUERY ---
        select_sql = ""

        if order_id_param:
            logging.info(f"🎯 Modo Francotirador: {order_id_param}")
            select_sql = f"SELECT DISTINCT order_id, purchase_date_mx FROM {table_ref} WHERE order_id = @order_id"
            query_parameters.append(bigquery.ScalarQueryParameter("order_id", "STRING", order_id_param))
            
        elif target_date_str:
            logging.info(f"📆 Modo Día Único: {target_date_str}")
            select_sql = f"SELECT DISTINCT order_id, purchase_date_mx FROM {table_ref} WHERE DATE(purchase_date_mx) = @target_date {extra_filter}"
            query_parameters.append(bigquery.ScalarQueryParameter("target_date", "STRING", target_date_str))
        
        elif days_ago_start and days_ago_end:
            s_val, e_val = int(days_ago_start), int(days_ago_end)
            logging.info(f"🗓️ Modo Ventana Móvil: De hace {s_val} a {e_val} días.")
            select_sql = f"""
            SELECT DISTINCT order_id, purchase_date_mx FROM {table_ref} 
            WHERE DATE(purchase_date_mx) BETWEEN DATE_SUB(CURRENT_DATE("America/Mexico_City"), INTERVAL @s_val DAY) 
              AND DATE_SUB(CURRENT_DATE("America/Mexico_City"), INTERVAL @e_val DAY) {extra_filter}
            """
            query_parameters.extend([
                bigquery.ScalarQueryParameter("s_val", "INT64", s_val),
                bigquery.ScalarQueryParameter("e_val", "INT64", e_val)
            ])

        elif start_date_str and end_date_str:
            logging.info(f"📅 Modo Rango Fijo: {start_date_str} a {end_date_str}")
            select_sql = f"SELECT DISTINCT order_id, purchase_date_mx FROM {table_ref} WHERE DATE(purchase_date_mx) BETWEEN @start_date AND @end_date {extra_filter}"
            query_parameters.extend([
                bigquery.ScalarQueryParameter("start_date", "STRING", start_date_str),
                bigquery.ScalarQueryParameter("end_date", "STRING", end_date_str)
            ])
            
        else:
            logging.info(f"🔎 Auditando últimos {window_days} días...")
            select_sql = f"""
            SELECT DISTINCT order_id, purchase_date_mx FROM {table_ref} 
            WHERE DATE(purchase_date_mx) >= DATE_SUB(CURRENT_DATE("America/Mexico_City"), INTERVAL @window_days DAY) {extra_filter}
            """
            query_parameters.append(bigquery.ScalarQueryParameter("window_days", "INT64", window_days))

        query_job = bq_client.query(select_sql, job_config=bigquery.QueryJobConfig(query_parameters=query_parameters))
        results = list(query_job.result())
        order_ids = [row["order_id"] for row in results]
        order_dates = {row["order_id"]: row["purchase_date_mx"] for row in results}
        
        total_orders = len(order_ids)
        logging.info(f"🎯 Total a auditar: {total_orders} SKUs con valores faltantes sospechosos.")

        if not order_ids:
            return (json.dumps({"status": "ok", "msg": "Nada por auditar."}), 200, {"Content-Type": "application/json"})

        # --- FUNCIÓN FLUSH (Solo Venta/Ingesta) ---
        def flush_updates(batch_data: Dict):
            if not batch_data: return 0
            count = 0
            for (oid, sku), d in batch_data.items():
                update_sql = f"""
                UPDATE {table_ref}
                SET
                  item_price_amount = @item_price_amount,
                  item_price_currency = @item_price_currency,
                  item_tax_amount = @item_tax_amount,
                  item_total_amount = @item_total_amount,
                  gross_revenue_amount = @gross_revenue_amount,
                  shipping_price_amount = @shipping_price_amount,
                  shipping_tax_amount = @shipping_tax_amount,
                  item_promotion_discount_amount = @item_promotion_discount_amount,
                  shipping_promotion_discount_amount = @shipping_promotion_discount_amount,
                  gift_wrap_price_amount = @gift_wrap_price_amount,
                  gift_wrap_tax_amount = @gift_wrap_tax_amount,
                  order_status = @order_status,
                  fulfillment_channel = @fulfillment_channel,
                  last_update_mx = CURRENT_DATETIME('America/Mexico_City')
                WHERE order_id = @order_id AND (seller_sku = @sku OR TRIM(seller_sku) = @sku)
                """
                params = [
                    bigquery.ScalarQueryParameter("item_price_amount", "NUMERIC", d.get("item_price_amount", 0)),
                    bigquery.ScalarQueryParameter("item_price_currency", "STRING", d.get("item_price_currency")),
                    bigquery.ScalarQueryParameter("item_tax_amount", "NUMERIC", d.get("item_tax_amount", 0)),
                    bigquery.ScalarQueryParameter("item_total_amount", "NUMERIC", d.get("item_total_amount", 0)),
                    bigquery.ScalarQueryParameter("gross_revenue_amount", "NUMERIC", d.get("gross_revenue_amount", 0)),
                    bigquery.ScalarQueryParameter("shipping_price_amount", "NUMERIC", d.get("shipping_price_amount", 0)),
                    bigquery.ScalarQueryParameter("shipping_tax_amount", "NUMERIC", d.get("shipping_tax_amount", 0)),
                    bigquery.ScalarQueryParameter("item_promotion_discount_amount", "NUMERIC", d.get("item_promotion_discount_amount", 0)),
                    bigquery.ScalarQueryParameter("shipping_promotion_discount_amount", "NUMERIC", d.get("shipping_promotion_discount_amount", 0)),
                    bigquery.ScalarQueryParameter("gift_wrap_price_amount", "NUMERIC", d.get("gift_wrap_price_amount", 0)),
                    bigquery.ScalarQueryParameter("gift_wrap_tax_amount", "NUMERIC", d.get("gift_wrap_tax_amount", 0)),
                    bigquery.ScalarQueryParameter("order_status", "STRING", d.get("order_status")),
                    bigquery.ScalarQueryParameter("fulfillment_channel", "STRING", d.get("fulfillment_channel")),
                    bigquery.ScalarQueryParameter("order_id", "STRING", oid),
                    bigquery.ScalarQueryParameter("sku", "STRING", sku),
                ]
                try:
                    bq_client.query(update_sql, job_config=bigquery.QueryJobConfig(query_parameters=params)).result()
                    count += 1
                except Exception as e:
                    if "streaming buffer" in str(e).lower():
                        logging.warning(f"⏩ Orden {oid} en streaming buffer. Reintentar luego.")
                    else:
                        logging.error(f"❌ Error BQ orden {oid}: {str(e)}")
            return count

        # --- PROCESAMIENTO ---
        access_token = get_access_token()
        total_rows_updated = 0
        ids_to_delete = []
        batch_to_update = {}

        for idx, order_id in enumerate(order_ids, start=1):
            if idx % 10 == 0: logging.info(f"⏳ Auditando {idx}/{total_orders}...")
            
            try:
                # 1. Obtener datos frescos de la Orders API
                order_resp = sp_api_request("GET", f"/orders/v0/orders/{order_id}", access_token)
                order_data = order_resp.get("payload")
                if not order_data:
                    logging.warning(f"⚠️ No hay payload para {order_id}")
                    continue
                
                # 2. Construir filas (reutilizando lógica de ingesta)
                rows = build_rows_from_orders([order_data], access_token)
                
                order_has_value = False
                for row in rows:
                    # Si alguna de las columnas clave tiene valor, se considera recuperada
                    if row.get("item_total_amount", 0) > 0 or row.get("item_price_amount", 0) > 0 or row.get("gross_revenue_amount", 0) > 0:
                        order_has_value = True
                    # Preparar update
                    batch_to_update[(order_id, row["seller_sku"])] = row

                # 3. Lógica de limpieza (30 días)
                if not order_has_value:
                    p_date_raw = order_dates.get(order_id)
                    if p_date_raw:
                        # BQ puede devolver objeto datetime o string
                        if isinstance(p_date_raw, datetime):
                            p_date = p_date_raw
                        else:
                            p_date = datetime.strptime(str(p_date_raw).replace("T", " ")[:19], "%Y-%m-%d %H:%M:%S")
                        
                        if p_date.tzinfo is None:
                            p_date = p_date.replace(tzinfo=MX_TZ)
                        
                        age_days = (datetime.now(MX_TZ) - p_date).days
                        if age_days > 30:
                            logging.warning(f"🗑️ Orden {order_id} sigue sin valores tras {age_days} días. Programando borrado.")
                            ids_to_delete.append(order_id)

                if len(batch_to_update) >= 50:
                    total_rows_updated += flush_updates(batch_to_update)
                    batch_to_update.clear()

            except Exception as e:
                logging.error(f"❌ Error auditando {order_id}: {str(e)}")
                continue

        if batch_to_update:
            total_rows_updated += flush_updates(batch_to_update)

        # 4. Limpieza de Stale Ceros
        if ids_to_delete:
            logging.info(f"🧹 Borrando {len(ids_to_delete)} órdenes stale...")
            ids_str = ", ".join([f"'{oid}'" for oid in ids_to_delete])
            delete_sql = f"DELETE FROM {table_ref} WHERE order_id IN ({ids_str})"
            bq_client.query(delete_sql).result()

        return (
            json.dumps({"status": "ok", "processed": total_orders, "updated": total_rows_updated, "deleted": len(ids_to_delete)}),
            200, {"Content-Type": "application/json"}
        )

    except Exception as e:
        logging.exception("Error Fatal en fix_ventas_amazon_zero")
        return (json.dumps({"error": str(e)}), 500, {"Content-Type": "application/json"})


# =========================
# ESTRATEGIA DE FECHAS
# =========================

def get_strategic_dates() -> list[str]:
    """
    Calcula las 9 fechas estratégicas para procesamiento eficiente:
    - Nivel Reciente: T-1 a T-7 (7 fechas)
    - Nivel Control Medio: T-15 (1 fecha)
    - Nivel Cierre: T-30 (1 fecha)
    
    Returns:
        Lista de 9 fechas en formato YYYY-MM-DD
    """
    now_mx = datetime.now(MX_TZ)
    dates = []
    
    # Nivel Reciente: Últimos 7 días
    for days_ago in range(1, 8):
        date_mx = (now_mx - timedelta(days=days_ago)).date()
        dates.append(date_mx.strftime("%Y-%m-%d"))
    
    # Nivel Control Medio: Día 15
    date_15 = (now_mx - timedelta(days=15)).date()
    dates.append(date_15.strftime("%Y-%m-%d"))
    
    # Nivel Cierre: Día 30
    date_30 = (now_mx - timedelta(days=30)).date()
    dates.append(date_30.strftime("%Y-%m-%d"))
    
    logging.info(f"📋 Fechas estratégicas calculadas (9 total): {', '.join(dates)}")
    return dates


# =========================
# FIX: FEES Y REFUNDS (Finances API)
# =========================

def _amount_from_dict(d: dict | None) -> float:
    """Extrae el monto, soportando 'Amount' (Orders API) y 'CurrencyAmount' (Finances API)."""
    if not d:
        return 0.0
    try:
        # Intenta primero con 'Amount' (Orders), si no, 'CurrencyAmount' (Finances)
        val = d.get("Amount")
        if val is None:
            val = d.get("CurrencyAmount")
            
        return round(float(val or 0), 2)
    except Exception:
        return 0.0

def fetch_financial_events_by_order(order_id: str, access_token: str) -> dict:
    """Llama a /finances/v0/orders/{orderId}/financialEvents"""
    endpoint = f"/finances/v0/orders/{order_id}/financialEvents"
    data = sp_api_request("GET", endpoint, access_token)
    return data.get("payload") or {}

def _ensure_fee_entry(fees_by_order_sku: Dict[Tuple[str, str], Dict[str, float]],
                      order_id: str, sku: str) -> Dict[str, float]:
    key = (order_id, sku)
    if key not in fees_by_order_sku:
        fees_by_order_sku[key] = {
            "referral_fee_amount": 0.0,
            "variable_closing_fee_amount": 0.0,
            "fba_fulfillment_fee_amount": 0.0,
            "shipping_label_fee_amount": 0.0,
            "other_transaction_fees_amount": 0.0,
            "tax_withheld_amount": 0.0,
            "marketplace_facilitator_tax_amount": 0.0,
            "principal_refund_amount": 0.0,
            "tax_refund_amount": 0.0,
            "shipping_refund_amount": 0.0,
            "shipping_tax_refund_amount": 0.0,
            "gift_wrap_refund_amount": 0.0,
            "gift_wrap_tax_refund_amount": 0.0,
            "restocking_fee_amount": 0.0,
            "gross_revenue_amount": 0.0,
        }
    return fees_by_order_sku[key]


def _map_fee_type_to_bucket(fee_type: str, amount: float, bucket: Dict[str, float]) -> None:
    """Mapea FeeType de Amazon a nuestras columnas y LOGUEA lo que encuentra."""
    ft = (fee_type or "").lower()
    
    # --- LOG DE DIAGNÓSTICO ---
    # Solo imprimiremos si el monto es distinto de 0 para no ensuciar logs
    if abs(amount) > 0.00:
        logging.info(f"🔍 DEBUG FEE: Tipo='{ft}' | Monto={amount}")

    if ft == "commission" or "referral" in ft:
        bucket["referral_fee_amount"] += amount
    elif "variableclosing" in ft or "closingfee" in ft:
        bucket["variable_closing_fee_amount"] += amount
    elif "fulfillment" in ft or "fba" in ft or "weightbased" in ft:
        bucket["fba_fulfillment_fee_amount"] += amount
    elif "shippingchargeback" in ft or "shippinglabel" in ft:
        bucket["shipping_label_fee_amount"] += amount
    elif "taxwithheld" in ft:
        bucket["tax_withheld_amount"] += amount
    elif "marketplacefacilitator" in ft:
        bucket["marketplace_facilitator_tax_amount"] += amount
    elif "giftwrapchargeback" in ft or "digitalservicesfee" in ft:
        # Estos son comunes y van a 'otros'
        bucket["other_transaction_fees_amount"] += amount
    else:
        # Si no reconocemos el fee, lo metemos en "otros" pero avisamos solo si es != 0
        if abs(amount) > 0.001:
            logging.warning(f"⚠️ FEE NO MAPEADO (se va a 'other'): {ft} = {amount}")
        bucket["other_transaction_fees_amount"] += amount


@functions_framework.http
def fix_ventas_amazon_fees(request):
    """
    FIX MAESTRO:
    - Batching: Guarda cada 50 órdenes (evita perder datos).
    - Interruptor: ?only_missing=true para rellenar huecos rápido.
    - Default: Revisa todo para capturar actualizaciones/refunds.
    """
    logging.basicConfig(level=logging.INFO)
    table_ref = f"`{PROJECT_ID}.{BQ_DATASET}.{BQ_TABLE}`"

    try:
        # --- PARÁMETROS ---
        order_id_param = request.args.get("order_id")
        target_date_str = request.args.get("target_date")
        start_date_str = request.args.get("start_date")
        end_date_str = request.args.get("end_date")
        days_param = request.args.get("days")
        
        # PARÁMETROS PARA VENTANAS MÓVILES (AUDITORÍA)
        days_ago_start = request.args.get("days_ago_start") 
        days_ago_end = request.args.get("days_ago_end")
        
        # EL NUEVO INTERRUPTOR
        # Si pones ?only_missing=true en la URL, se activa el modo rápido
        only_missing = request.args.get("only_missing") == "true"
        
        window_days = int(days_param) if days_param else 60
        if window_days < 1: window_days = 1
        if window_days > 180: window_days = 180

        query_parameters = []
        
        # Construcción del filtro SQL condicional
        extra_filter = ""
        if only_missing:
            logging.info("🚀 MODO RELLENO ACTIVADO: Saltando órdenes que ya tienen datos.")
            extra_filter = "AND (referral_fee_amount IS NULL OR referral_fee_amount = 0)"
        else:
            logging.info("🐢 MODO COMPLETO: Revisando todas las órdenes (incluye actualizaciones y refunds).")

        # --- CONSTRUCCIÓN DEL QUERY ---
        if order_id_param:
            logging.info(f"🎯 Modo Francotirador: {order_id_param}")
            select_sql = f"SELECT DISTINCT order_id FROM {table_ref} WHERE order_id = @order_id"
            query_parameters.append(bigquery.ScalarQueryParameter("order_id", "STRING", order_id_param))
            
        elif target_date_str:
            logging.info(f"📆 Modo Día Único: {target_date_str}")
            select_sql = f"""
            SELECT DISTINCT order_id 
            FROM {table_ref} 
            WHERE DATE(purchase_date_mx) = @target_date 
              {extra_filter}
            """
            query_parameters.append(bigquery.ScalarQueryParameter("target_date", "STRING", target_date_str))
            
        # --- NUEVA LÓGICA: VENTANA MÓVIL ---
        elif days_ago_start and days_ago_end:
            s_val = int(days_ago_start)
            e_val = int(days_ago_end)
            logging.info(f"🗓️ Modo Ventana Móvil: De hace {s_val} días hasta hace {e_val} días.")
            
            select_sql = f"""
            SELECT DISTINCT order_id FROM {table_ref} 
            WHERE purchase_date_mx IS NOT NULL 
              AND DATE(purchase_date_mx) BETWEEN DATE_SUB(CURRENT_DATE("America/Mexico_City"), INTERVAL @s_val DAY) 
              AND DATE_SUB(CURRENT_DATE("America/Mexico_City"), INTERVAL @e_val DAY)
              {extra_filter}
            """
            query_parameters.append(bigquery.ScalarQueryParameter("s_val", "INT64", s_val))
            query_parameters.append(bigquery.ScalarQueryParameter("e_val", "INT64", e_val))

        elif start_date_str and end_date_str:
            logging.info(f"📅 Modo Rango: {start_date_str} a {end_date_str}")
            select_sql = f"""
            SELECT DISTINCT order_id 
            FROM {table_ref} 
            WHERE purchase_date_mx IS NOT NULL 
              AND DATE(purchase_date_mx) BETWEEN @start_date AND @end_date
              {extra_filter}
            """
            query_parameters.append(bigquery.ScalarQueryParameter("start_date", "STRING", start_date_str))
            query_parameters.append(bigquery.ScalarQueryParameter("end_date", "STRING", end_date_str))
            
        else:
            # --- MODO ESTRATÉGICO: 9 FECHAS PUNTUALES ---
            logging.info("🎯 Modo Estratégico: Procesando 9 fechas (T-1 a T-7, T-15, T-30)")
            strategic_dates = get_strategic_dates()
            
            # Construir parámetros para query IN
            dates_param = [bigquery.ScalarQueryParameter(f"date_{i}", "STRING", date) 
                          for i, date in enumerate(strategic_dates)]
            query_parameters.extend(dates_param)
            
            # Construir condición IN
            date_placeholders = ", ".join([f"@date_{i}" for i in range(len(strategic_dates))])
            
            select_sql = f"""
            SELECT DISTINCT order_id FROM {table_ref} 
            WHERE purchase_date_mx IS NOT NULL 
              AND DATE(purchase_date_mx) IN ({date_placeholders})
              {extra_filter}
            """

        job_config = bigquery.QueryJobConfig(query_parameters=query_parameters)
        query_job = bq_client.query(select_sql, job_config=job_config)
        order_ids = [row["order_id"] for row in query_job.result()]
        
        total_orders = len(order_ids)
        logging.info(f"🎯 Total a procesar: {total_orders}")

        if not order_ids:
            return (json.dumps({"status": "ok", "msg": "Nada por procesar aquí."}), 200, {"Content-Type": "application/json"})

        # --- FUNCIÓN DE GUARDADO (Flush) ---
        def flush_updates(batch_data: Dict):
            if not batch_data: return 0
            count_updates = 0
            for (oid, sku), d in batch_data.items():
                if sum(abs(x) for x in d.values()) == 0: continue
                
                update_sql = f"""
                UPDATE {table_ref}
                SET
                  referral_fee_amount = @referral_fee_amount,
                  variable_closing_fee_amount = @variable_closing_fee_amount,
                  fba_fulfillment_fee_amount = @fba_fulfillment_fee_amount,
                  shipping_label_fee_amount = @shipping_label_fee_amount,
                  other_transaction_fees_amount = @other_transaction_fees_amount,
                  tax_withheld_amount = @tax_withheld_amount,
                  marketplace_facilitator_tax_amount = @marketplace_facilitator_tax_amount,
                  principal_refund_amount = @principal_refund_amount,
                  tax_refund_amount = @tax_refund_amount,
                  shipping_refund_amount = @shipping_refund_amount,
                  shipping_tax_refund_amount = @shipping_tax_refund_amount,
                  gift_wrap_refund_amount = @gift_wrap_refund_amount,
                  gift_wrap_tax_refund_amount = @gift_wrap_tax_refund_amount,
                  restocking_fee_amount = @restocking_fee_amount,
                  gross_revenue_amount = @gross_revenue_amount,
                  last_update_mx = CURRENT_DATETIME('America/Mexico_City')
                WHERE order_id = @order_id
                  AND TRIM(seller_sku) = @sku
                """
                job_conf = bigquery.QueryJobConfig(
                    query_parameters=[
                        bigquery.ScalarQueryParameter("referral_fee_amount", "NUMERIC", d["referral_fee_amount"]),
                        bigquery.ScalarQueryParameter("variable_closing_fee_amount", "NUMERIC", d["variable_closing_fee_amount"]),
                        bigquery.ScalarQueryParameter("fba_fulfillment_fee_amount", "NUMERIC", d["fba_fulfillment_fee_amount"]),
                        bigquery.ScalarQueryParameter("shipping_label_fee_amount", "NUMERIC", d["shipping_label_fee_amount"]),
                        bigquery.ScalarQueryParameter("other_transaction_fees_amount", "NUMERIC", d["other_transaction_fees_amount"]),
                        bigquery.ScalarQueryParameter("tax_withheld_amount", "NUMERIC", d["tax_withheld_amount"]),
                        bigquery.ScalarQueryParameter("marketplace_facilitator_tax_amount", "NUMERIC", d["marketplace_facilitator_tax_amount"]),
                        bigquery.ScalarQueryParameter("principal_refund_amount", "NUMERIC", d["principal_refund_amount"]),
                        bigquery.ScalarQueryParameter("tax_refund_amount", "NUMERIC", d["tax_refund_amount"]),
                        bigquery.ScalarQueryParameter("shipping_refund_amount", "NUMERIC", d["shipping_refund_amount"]),
                        bigquery.ScalarQueryParameter("shipping_tax_refund_amount", "NUMERIC", d["shipping_tax_refund_amount"]),
                        bigquery.ScalarQueryParameter("gift_wrap_refund_amount", "NUMERIC", d["gift_wrap_refund_amount"]),
                        bigquery.ScalarQueryParameter("gift_wrap_tax_refund_amount", "NUMERIC", d["gift_wrap_tax_refund_amount"]),
                        bigquery.ScalarQueryParameter("restocking_fee_amount", "NUMERIC", d["restocking_fee_amount"]),
                        bigquery.ScalarQueryParameter("gross_revenue_amount", "NUMERIC", d["gross_revenue_amount"]),
                        bigquery.ScalarQueryParameter("order_id", "STRING", oid),
                        bigquery.ScalarQueryParameter("sku", "STRING", sku), 
                    ]
                )
                try:
                    bq_client.query(update_sql, job_config=job_conf).result()
                    count_updates += 1
                except Exception as e:
                    err_msg = str(e)
                    if "streaming buffer" in err_msg.lower():
                        logging.warning(f"⏩ Orden {oid} en buffer de streaming. Se actualizará en la próxima corrida.")
                    else:
                        logging.error(f"❌ Error BigQuery en orden {oid}: {err_msg}")
            return count_updates

        # --- PROCESAMIENTO ---
        access_token = get_access_token()
        fees_batch: Dict[Tuple[str, str], Dict[str, float]] = {}
        total_rows_updated = 0
        BATCH_SIZE = 50 

        for idx, order_id in enumerate(order_ids, start=1):
            if idx % 10 == 0: 
                logging.info(f"⏳ Procesando {idx}/{total_orders}...")

            try:
                payload = fetch_financial_events_by_order(order_id, access_token)
                financial_events = (payload.get("FinancialEvents") or {})
                
                # Unificar eventos de envío y de reembolso
                events_to_check = (financial_events.get("ShipmentEventList", []) or []) + \
                                  (financial_events.get("RefundEventList", []) or [])

                for event in events_to_check:
                    items = event.get("ShipmentItemList") or event.get("ShipmentItemAdjustmentList") or []
                    for item in items:
                        sku = item.get("SellerSKU")
                        if not sku: continue
                        sku_clean = sku.strip()
                        bucket = _ensure_fee_entry(fees_batch, order_id, sku_clean)
                        
                        # 1. Fees normales
                        for fee in item.get("ItemFeeList") or []:
                             _map_fee_type_to_bucket(fee.get("FeeType"), _amount_from_dict(fee.get("FeeAmount")), bucket)
                        
                        # 2. Fees de ajuste (en reembolsos)
                        for fee_adj in item.get("ItemFeeAdjustmentList") or []:
                             _map_fee_type_to_bucket(fee_adj.get("FeeType"), _amount_from_dict(fee_adj.get("FeeAmount")), bucket)
                        
                        # 3. Cargos ajustados (Principal, Tax, etc.) - REEMBOLSOS
                        for charge_adj in item.get("ItemChargeAdjustmentList") or []:
                            c_type = (charge_adj.get("ChargeType") or "").lower()
                            amt = _amount_from_dict(charge_adj.get("ChargeAmount"))
                            if "principal" in c_type: 
                                bucket["principal_refund_amount"] += amt
                                bucket["gross_revenue_amount"] += amt
                            elif "tax" == c_type: 
                                bucket["tax_refund_amount"] += amt
                                bucket["gross_revenue_amount"] += amt
                            elif "shippingtax" in c_type: 
                                bucket["shipping_tax_refund_amount"] += amt
                                bucket["gross_revenue_amount"] += amt
                            elif "shipping" in c_type: 
                                bucket["shipping_refund_amount"] += amt
                                bucket["gross_revenue_amount"] += amt
                            elif "giftwraptax" in c_type: 
                                bucket["gift_wrap_tax_refund_amount"] += amt
                                bucket["gross_revenue_amount"] += amt
                            elif "giftwrap" in c_type: 
                                bucket["gift_wrap_refund_amount"] += amt
                                bucket["gross_revenue_amount"] += amt
                            elif "restocking" in c_type: 
                                bucket["restocking_fee_amount"] += amt

                        # 4. Cargos Normales (Principal, Tax, Shipping) - VENTAS
                        for charge in item.get("ItemChargeList") or []:
                            c_type = (charge.get("ChargeType") or "").lower()
                            amt = _amount_from_dict(charge.get("ChargeAmount"))
                            if any(x in c_type for x in ["principal", "tax", "shipping", "giftwrap"]):
                                bucket["gross_revenue_amount"] += amt
                        
                        # 5. Promociones (Suelen ser negativas y restan del gross revenue)
                        for promo in item.get("PromotionList") or []:
                            amt = _amount_from_dict(promo.get("PromotionAmount"))
                            bucket["gross_revenue_amount"] += amt

                # Checkpoint Batch
                if len(fees_batch) >= BATCH_SIZE:
                    logging.info(f"💾 Guardando lote de {len(fees_batch)} SKUs...")
                    saved = flush_updates(fees_batch)
                    total_rows_updated += saved
                    fees_batch.clear()

            except Exception as e:
                logging.error(f"❌ Error procesando orden {order_id}: {str(e)}")
                # Continuamos con la siguiente orden para no abortar todo
                continue

        # Checkpoint Final
        if fees_batch:
            try:
                logging.info(f"💾 Guardando lote final de {len(fees_batch)} SKUs...")
                saved = flush_updates(fees_batch)
                total_rows_updated += saved
            except Exception as e:
                logging.error(f"❌ Error en lote final: {str(e)}")

        return (
            json.dumps({
                "status": "ok", 
                "orders_processed": total_orders,
                "rows_modified_in_bq": total_rows_updated,
                "mode": "only_missing" if only_missing else "full_update"
            }),
            200,
            {"Content-Type": "application/json"},
        )

    except Exception as e:
        logging.exception("Error en fix_ventas_amazon_fees")
        return (json.dumps({"error": str(e)}), 500, {"Content-Type": "application/json"})
        
# =========================
# ENTRYPOINT HTTP PRINCIPAL
# =========================

@functions_framework.http
def main(request):
    """
    Cloud Function HTTP Gen2:

    - Renueva token de Amazon
    - Obtiene órdenes de AYER (MX) + sus items
    - Convierte fechas a MX
    - Inserta 1 fila por ítem en ml_cs.ventas_amazon
    """
    logging.basicConfig(level=logging.INFO)

    try:
        access_token = get_access_token()
        orders = fetch_orders_for_yesterday(access_token)
        rows = build_rows_from_orders(orders, access_token)
        errors = insert_rows_bigquery(rows)

        response = {
            "dataset": BQ_DATASET,
            "table": BQ_TABLE,
            "rows_ready": len(rows),
            "insert_errors": errors,
        }
        return (json.dumps(response), 200, {"Content-Type": "application/json"})

    except Exception as e:
        logging.exception("Error en Cloud Function Amazon SP-API")
        return (
            json.dumps({"error": str(e)}),
            500,
            {"Content-Type": "application/json"},
        )