# Sincronizacion y Despliegue
Param([string]$Target)

$PROJECT_ID = "base-cs-478820"
$REGION = "europe-west1"

# Configuración de Funciones
if ($Target -eq "Amazon") { $FN = "ingestar-ventas-amazon"; $ENTRY = "main"; $DIR = "ventas/Amazon"; $TYPE = "function" }
elseif ($Target -eq "Mercadolibre") { $FN = "ingestar-ventas-ml"; $ENTRY = "ingestar_ventas_ml"; $DIR = "ventas/Mercadolibre"; $TYPE = "function" }
elseif ($Target -eq "Shopify") { $FN = "ingestar-ventas-shopify"; $ENTRY = "main"; $DIR = "ventas/Shopify"; $TYPE = "function" }
elseif ($Target -eq "Amazon_Fees") { $FN = "fix-ventas-amazon-fees"; $ENTRY = "fix_ventas_amazon_fees"; $DIR = "ventas/Amazon"; $TYPE = "function" }
elseif ($Target -eq "Amazon_Zero") { $FN = "fix-ventas-amazon-zero"; $ENTRY = "fix_ventas_amazon_zero"; $DIR = "ventas/Amazon"; $TYPE = "function" }
elseif ($Target -eq "Amazon_All") { 
    Write-Host "🚀 Desplegando TODAS las funciones de Amazon..." -ForegroundColor Cyan
    .\desplegar.ps1 -Target Amazon
    Write-Host "Esperando 10 segundos antes del siguiente despliegue..." -ForegroundColor Gray
    Start-Sleep -Seconds 10
    .\desplegar.ps1 -Target Amazon_Fees
    Write-Host "Esperando 10 segundos antes del siguiente despliegue..." -ForegroundColor Gray
    Start-Sleep -Seconds 10
    .\desplegar.ps1 -Target Amazon_Zero
    exit 
}
elseif ($Target -eq "Dashboard") { $TYPE = "run" }
else { Write-Host "Uso: .\desplegar.ps1 -Target Amazon|Mercadolibre|Shopify|Dashboard|Amazon_Fees|Amazon_Zero"; exit }

Write-Host "Iniciando despliegue de $Target..." -ForegroundColor Cyan

if (Test-Path "credenciales.json") {
    & gcloud auth activate-service-account --key-file=credenciales.json --quiet
    & gcloud config set project $PROJECT_ID --quiet
}

if ($TYPE -eq "function") {
    $deployDir = $DIR
    Set-Location $deployDir
    & gcloud functions deploy $FN --gen2 --runtime=python311 --region=$REGION --entry-point=$ENTRY --trigger-http --allow-unauthenticated --timeout=3600 --memory=512MiB --quiet
    Set-Location ..\..
}
elseif ($TYPE -eq "run") {
    Write-Host "Desplegando App en Cloud Run..." -ForegroundColor Yellow
    & gcloud run deploy dashboard-ventas --source . --region=$REGION --allow-unauthenticated --quiet
}

Write-Host "Proceso completado para $Target" -ForegroundColor Green
