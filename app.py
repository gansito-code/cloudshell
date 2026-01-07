import os
from flask import Flask, render_template, jsonify
from google.cloud import bigquery

app = Flask(__name__)

# Configuración de Google Cloud
os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = "credenciales.json"
PROJECT_ID = "base-cs-478820"
DATASET_ID = "ml_cs"

client = bigquery.Client(project=PROJECT_ID)

def get_recent_data(table_name, limit=10):
    """Obtiene los registros más recientes de una tabla específica."""
    try:
        # Mapeo profesional de columnas segun el SCHEMA REAL en BigQuery
        config = {
            "ventas_amazon": {"date": "purchase_date_mx", "id": "order_id", "total": "gross_revenue_amount"},
            "ventas_vertical": {"date": "fecha_venta", "id": "id_orden", "total": "total"},
            "ventas_shopify": {"date": "purchase_date_mx", "id": "order_name", "total": "line_total_amount"}
        }
        
        c = config.get(table_name)
        if not c: return []

        query = f"""
            SELECT {c['date']} as fecha, {c['id']} as id, {c['total']} as monto 
            FROM `{PROJECT_ID}.{DATASET_ID}.{table_name}` 
            ORDER BY {c['date']} DESC 
            LIMIT {limit}
        """
        
        query_job = client.query(query)
        results = query_job.result()
        
        data = []
        for row in results:
            item = dict(row.items())
            for key, value in item.items():
                if hasattr(value, 'isoformat'):
                    item[key] = value.isoformat()
            data.append(item)
        return data
    except Exception as e:
        print(f"Error consultando {table_name}: {e}")
        return []

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/data')
def data():
    return jsonify({
        "amazon": get_recent_data("ventas_amazon"),
        "ml": get_recent_data("ventas_vertical"),
        "shopify": get_recent_data("ventas_shopify")
    })

@app.route('/api/stats')
def stats():
    def count(table):
        try:
            q = f"SELECT COUNT(*) as total FROM `{PROJECT_ID}.{DATASET_ID}.{table}`"
            return list(client.query(q).result())[0].total
        except: return 0
    return jsonify({
        "amazon": count("ventas_amazon"),
        "ml": count("ventas_vertical"),
        "shopify": count("ventas_shopify")
    })

if __name__ == '__main__':
    print("🚀 Dashboard iniciado en http://localhost:5000")
    app.run(debug=True, port=5000)
