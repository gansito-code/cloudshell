# Sincronizacion con Google Cloud
Write-Host "Iniciando Sincronizacion..." -ForegroundColor Cyan

$PROJECT_ID = "base-cs-478820"
$REGION = "europe-west1"

# 1. Autenticar
if (Test-Path "credenciales.json") {
    Write-Host "Usando credenciales.json..." -ForegroundColor Green
    & gcloud auth activate-service-account --key-file=credenciales.json --quiet
    & gcloud config set project $PROJECT_ID --quiet
}

# 2. Descargar
$mappings = @{
    "ingestar-ventas-amazon"  = "Amazon"
    "ingestar-ventas-ml"      = "Mercadolibre"
    "ingestar-ventas-shopify" = "Shopify"
    "fix-ventas-amazon-fees"  = "Amazon"
    "fix-ventas-amazon-zero"  = "Amazon"
}

foreach ($key in $mappings.Keys) {
    $folder = $mappings[$key]
    Write-Host "Sincronizando $folder ($key)..." -ForegroundColor Yellow

    $cmd = "gcloud functions describe $key --region $REGION --format='value(buildConfig.source.storageSource.bucket,buildConfig.source.storageSource.object)'"
    $source = Invoke-Expression $cmd
    
    if ($source) {
        # Dividir por cualquier espacio en blanco (tabulador o espacio)
        $parts = $source.Trim() -split "\s+"
        $bucket = $parts[0]
        $object = $parts[1]
        
        if (!(Test-Path $folder)) { New-Item -ItemType Directory $folder }
        $zipPath = Join-Path $folder "source.zip"
        
        $gsPath = "gs://$bucket/$object"
        Write-Host "   Descargando $gsPath"
        & gsutil cp $gsPath $zipPath
        
        if (Test-Path $zipPath) {
            Write-Host "   Extrayendo..."
            Expand-Archive -Path $zipPath -DestinationPath $folder -Force
            Remove-Item $zipPath
            Write-Host "OK: $folder" -ForegroundColor Green
        }
        else {
            Write-Host "ERROR: No se descargo el archivo para $folder" -ForegroundColor Red
        }
    }
    else {
        Write-Host "ERROR: No se encontro info de $key" -ForegroundColor Red
    }
}

Write-Host "Sincronizacion completa" -ForegroundColor Cyan
