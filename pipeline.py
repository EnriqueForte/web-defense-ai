# pipeline.py
# ============================================================
# Pipeline automatizado del Sistema de Defensa Web
# Ejecuta el análisis cada N minutos de forma continua
# ============================================================

import os
import time
import subprocess
from datetime import datetime
from pathlib import Path
from dotenv import load_dotenv
from config.notifications import notificar_alerta_critica

load_dotenv()

# Importar configuración centralizada
from config.settings import (
    LOG_PATH, REPORT_PATH, INTERVALO_MINUTOS,
    SEVERIDADES_CRITICAS
)

# ============================================================
# COLORES PARA LA CONSOLA (sin dependencias externas)
# ============================================================
class Color:
    ROJO    = "\033[91m"
    VERDE   = "\033[92m"
    AMARILLO= "\033[93m"
    AZUL    = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN    = "\033[96m"
    RESET   = "\033[0m"
    NEGRITA = "\033[1m"

def imprimir_banner():
    print(f"""
{Color.CYAN}{Color.NEGRITA}
╔══════════════════════════════════════════════════════════════╗
║       SISTEMA DE DEFENSA WEB CON AGENTES DE IA               ║
║                    BY T3r0S3c                                ║
║              Pipeline Automatizado v1.0                      ║
╚══════════════════════════════════════════════════════════════╝
{Color.RESET}""")

def sincronizar_log():
    """
    Copia el access.log del contenedor DVWA al proyecto.
    Equivalente a ejecutar sync_logs.ps1 desde Python.
    """
    print(f"{Color.AZUL}🔄 Sincronizando log desde DVWA...{Color.RESET}")
    
    resultado = subprocess.run(
        ["docker", "cp", "dvwa-app:/var/log/apache2/access.log", LOG_PATH],
        capture_output=True,
        text=True
    )
    
    if resultado.returncode == 0:
        # Contar líneas del log
        lineas = Path(LOG_PATH).read_text(
            encoding="utf-8", errors="replace"
        ).splitlines()
        print(f"{Color.VERDE}   ✅ Log sincronizado: {len(lineas)} líneas{Color.RESET}")
        return True
    else:
        print(f"{Color.ROJO}   ❌ Error al sincronizar: {resultado.stderr}{Color.RESET}")
        return False

def ejecutar_analisis():
    """
    Ejecuta main.py y captura el resultado.
    Retorna el contenido del reporte generado.
    """
    print(f"{Color.AZUL}🤖 Ejecutando análisis con agentes de IA...{Color.RESET}")
    
    resultado = subprocess.run(
        [os.path.join(".venv", "Scripts", "python.exe"), "main.py"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        env={**os.environ, "PYTHONIOENCODING": "utf-8"}
    )
    
    if resultado.returncode != 0:
        print(f"{Color.ROJO}❌ Error en el análisis:{Color.RESET}")
        print(resultado.stderr[-500:])  # Últimas 500 chars del error
        return None
    
    return resultado.stdout

def leer_reporte() -> str:
    """
    Lee el reporte más reciente generado por los agentes.
    """
    ruta = Path(REPORT_PATH) / "reporte_seguridad.md"
    if ruta.exists():
        return ruta.read_text(encoding="utf-8")
    return ""

def analizar_alertas_criticas(reporte: str) -> list[str]:
    """
    Escanea el reporte buscando amenazas críticas o altas
    para mostrar alertas inmediatas en la consola.
    """
    alertas = []
    lineas = reporte.splitlines()
    
    for linea in lineas:
        for severidad in SEVERIDADES_CRITICAS:
            if severidad in linea.upper() and "|" in linea:
                alertas.append(linea.strip())
                break
    
    return alertas

def mostrar_resumen(reporte: str, numero_ciclo: int):
    """
    Muestra un resumen visual del reporte en la consola.
    """
    from config.notifications import notificar_alerta_critica  # ← import aquí

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    print(f"\n{Color.CYAN}{'='*60}{Color.RESET}")
    print(f"{Color.NEGRITA}Resumen del Ciclo #{numero_ciclo} - {timestamp}{Color.RESET}")
    print(f"{Color.CYAN}{'='*60}{Color.RESET}")
    
    # Buscar y mostrar alertas criticas
    alertas = analizar_alertas_criticas(reporte)
    
    if alertas:
        print(f"\n{Color.ROJO}{Color.NEGRITA}ALERTAS DETECTADAS:{Color.RESET}")
        for alerta in alertas[:10]:
            if "CRITICA" in alerta.upper():
                print(f"  {Color.ROJO}> {alerta}{Color.RESET}")
            elif "ALTA" in alerta.upper():
                print(f"  {Color.AMARILLO}> {alerta}{Color.RESET}")
        
        # Disparar notificaciones Telegram + Email
        notificar_alerta_critica(alertas, numero_ciclo)  # notificaciones en telegram y correo
    else:
        print(f"\n{Color.VERDE}Sin amenazas criticas detectadas{Color.RESET}")
    
    # Mostrar ruta del reporte
    ruta_reporte = Path(REPORT_PATH) / "reporte_seguridad.md"
    print(f"\n{Color.VERDE}Reporte completo: {ruta_reporte}{Color.RESET}")

def guardar_historial(reporte: str, numero_ciclo: int):
    """
    Guarda una copia histórica de cada reporte con timestamp.
    Permite revisar la evolución de las amenazas en el tiempo.
    """
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    historial_dir = Path(REPORT_PATH) / "historial"
    historial_dir.mkdir(exist_ok=True)
    
    ruta_historial = historial_dir / f"reporte_{timestamp}_ciclo{numero_ciclo}.md"
    ruta_historial.write_text(reporte, encoding="utf-8")
    
    print(f"{Color.AZUL}📁 Historial guardado: {ruta_historial.name}{Color.RESET}")

# ============================================================
# BUCLE PRINCIPAL DEL PIPELINE
# ============================================================
def main():
    imprimir_banner()
    
    print(f"{Color.AMARILLO}⚙️  Configuración:{Color.RESET}")
    print(f"   Intervalo de análisis : {INTERVALO_MINUTOS} minutos")
    print(f"   Log fuente            : {LOG_PATH}")
    print(f"   Reportes en           : {REPORT_PATH}")
    print(f"\n{Color.AMARILLO}Presiona Ctrl+C para detener el pipeline{Color.RESET}\n")
    
    numero_ciclo = 0
    
    while True:
        numero_ciclo += 1
        timestamp = datetime.now().strftime("%H:%M:%S")
        
        print(f"\n{Color.MAGENTA}{'─'*60}")
        print(f"🔁 CICLO #{numero_ciclo} — {timestamp}")
        print(f"{'─'*60}{Color.RESET}\n")
        
        # PASO 1: Sincronizar log desde Docker
        if not sincronizar_log():
            print(f"{Color.AMARILLO}⏭️  Saltando ciclo por error de sincronización{Color.RESET}")
            time.sleep(30)
            continue
        
        # PASO 2: Ejecutar análisis con agentes
        output = ejecutar_analisis()
        
        if output is None:
            print(f"{Color.AMARILLO}⏭️  Saltando ciclo por error en el análisis{Color.RESET}")
        else:
            # PASO 3: Leer y mostrar resumen del reporte
            reporte = leer_reporte()
            
            if reporte:
                mostrar_resumen(reporte, numero_ciclo)
                guardar_historial(reporte, numero_ciclo)
            
        # PASO 4: Esperar hasta el próximo ciclo
        print(f"\n{Color.AZUL}⏳ Próximo análisis en {INTERVALO_MINUTOS} "
              f"minuto(s)... (Ctrl+C para detener){Color.RESET}")
        
        time.sleep(INTERVALO_MINUTOS * 60)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n{Color.AMARILLO}🛑 Pipeline detenido por el usuario{Color.RESET}")
        print(f"{Color.VERDE}✅ Sistema de defensa desactivado correctamente{Color.RESET}\n")