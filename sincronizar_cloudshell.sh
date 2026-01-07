#!/bin/bash

# Script de Sincronizacion COMPLETO para Cloud Shell (Linux)
# Configurado para base-cs-478820 y region europe-west1

echo "------------------------------------------------"
echo "🚀 Iniciando Sincronizacion en Cloud Shell..."
echo "------------------------------------------------"

PROJECT_ID="base-cs-478820"
REGION="europe-west1"

# Asegurar proyecto correcto
gcloud config set project $PROJECT_ID --quiet

# 1. Sincronizar Funciones
declare -A mappings=( 
    ["ingestar-ventas-amazon"]="ventas/Amazon" 
    ["ingestar-ventas-ml"]="ventas/Mercadolibre" 
    ["ingestar-ventas-shopify"]="ventas/Shopify" 
    ["fix-ventas-amazon-fees"]="ventas/Amazon"
    ["fix-ventas-amazon-zero"]="ventas/Amazon"
)

for fnName in "${!mappings[@]}"; do
    folder="${mappings[$fnName]}"
    echo "⬇️ Sincronizando funcion: $folder..."

    # Obtener info sin usar modificadores de formato complejos que fallan en shell
    raw_source=$(gcloud functions describe $fnName --region $REGION --format="value(buildConfig.source.storageSource.bucket,buildConfig.source.storageSource.object)")
    
    if [ ! -z "$raw_source" ]; then
        # Parsear con read para evitar errores de espacios/tabs
        read -r bucket object <<< "$raw_source"
        
        mkdir -p "$folder"
        zip_path="$folder/source_fn.zip"
        
        gsutil cp "gs://$bucket/$object" "$zip_path"
        unzip -o "$zip_path" -d "$folder"
        rm "$zip_path"
        echo "✅ $folder sincronizado correctamente."
    else
        echo "❌ Error: No se encontro el codigo de $fnName"
    fi
done

# 2. Sincronizar Dashboard (Cloud Run)
echo "⬇️ Sincronizando Dashboard (Cloud Run)..."

raw_run=$(gcloud run services describe dashboard-ventas --region $REGION --format="value(metadata.annotations.'run.googleapis.com/build-source-location')")

if [ ! -z "$raw_run" ]; then
    # El formato es gs://bucket/object#generation
    gs_uri=$(echo $raw_run | cut -d'#' -f1)
    
    mkdir -p "Dashboard_Src"
    zip_path="Dashboard_Src/source_run.zip"
    
    gsutil cp "$gs_uri" "$zip_path"
    unzip -o "$zip_path" -d "."
    rm "$zip_path"
    echo "✅ Archivos del Dashboard sincronizados en la raiz."
else
    echo "❌ Error: No se encontro el origen del Dashboard."
fi

echo ""
echo "✨ Sincronizacion completa en Cloud Shell con exito."
