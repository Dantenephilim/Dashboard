# Imagen base ligera de Python optimizada para producción
FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PORT=8090

WORKDIR /app

# Instalar curl para healthcheck y utilidades básicas
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    git \
    && rm -rf /var/lib/apt/lists/*

# Copiar e instalar dependencias
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copiar código de la aplicación y script de actualización
COPY app/ ./app/
COPY update.sh ./update.sh
RUN chmod +x update.sh

# Exponer el puerto 8090
EXPOSE 8090

# Comprobación de salud interna en el puerto 8090
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD curl -f http://127.0.0.1:8090/api/ping || exit 1

# Inicio del servidor Uvicorn fijado al puerto 8090
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8090"]
