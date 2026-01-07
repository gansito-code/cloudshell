FROM python:3.11-slim

# Evitar que Python genere archivos .pyc y permitir logs en tiempo real
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

WORKDIR /app

# Copiar requerimientos e instalar dependencias
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copiar el resto de la aplicación
COPY app.py .
COPY credenciales.json .
COPY templates/ ./templates/
COPY static/ ./static/

# Configurar el puerto para Cloud Run (por defecto 8080)
ENV PORT=8080

# Comando para iniciar la aplicación con Gunicorn para producción
CMD exec gunicorn --bind :$PORT --workers 1 --threads 8 --timeout 0 app:app
