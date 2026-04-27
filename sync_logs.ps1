# sync_logs.ps1
# Sincroniza el log de DVWA al proyecto antes de cada análisis

Write-Host "🔄 Sincronizando logs desde DVWA..." -ForegroundColor Cyan

docker cp dvwa-app:/var/log/apache2/access.log ./logs/access.log

if ($?) {
    $lineas = (Get-Content .\logs\access.log).Count
    Write-Host "✅ Log sincronizado: $lineas líneas" -ForegroundColor Green
}
else {
    Write-Host "❌ Error al sincronizar el log" -ForegroundColor Red
}