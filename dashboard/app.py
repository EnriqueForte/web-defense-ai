# dashboard/app.py
# ============================================================
# Servidor Flask — Dashboard de Defensa Web T3r0S3c
# ============================================================

import os
import json
import sys
import subprocess
from pathlib import Path
from datetime import datetime
from flask import Flask, render_template, jsonify
from dotenv import load_dotenv

# Añadir raíz del proyecto al path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

load_dotenv()

app = Flask(__name__)

# ============================================================
# CONFIGURACIÓN
# ============================================================
REPORT_PATH  = Path(os.getenv("REPORT_PATH", "./reports"))
LOG_PATH     = os.getenv("LOG_PATH", "./logs/access.log")
HISTORIAL    = REPORT_PATH / "historial"
VENV_PYTHON  = os.path.join(".venv", "Scripts", "python.exe")


# ============================================================
# FUNCIONES DE SOPORTE
# ============================================================
def parsear_amenazas(reporte: str) -> list[dict]:
    """
    Extrae amenazas del reporte. Detecta el orden de columnas
    dinamicamente leyendo la cabecera real de la tabla.
    """
    amenazas  = []
    lineas    = reporte.splitlines()
    en_tabla  = False
    cabeceras = []
    ips_log   = extraer_ips_del_log()

    for linea in lineas:
        if "AMENAZAS DETECTADAS" in linea.upper():
            en_tabla  = True
            cabeceras = []
            continue

        if not en_tabla:
            continue

        if "---" in linea:
            continue

        # Leer cabeceras de la primera fila de la tabla
        if linea.startswith("|") and not cabeceras:
            cabeceras = [
                c.strip().lower()
                .replace("á","a").replace("é","e")
                .replace("í","i").replace("ó","o")
                .replace("ú","u").replace("ã","a")
                .replace("lã\xadnea","linea")
                for c in linea.split("|") if c.strip()
            ]
            continue

        # Procesar filas de datos
        if linea.startswith("|") and cabeceras:
            partes = [p.strip() for p in linea.split("|") if p.strip()]
            if len(partes) < 3:
                continue

            # Buscar índice de cada columna por nombre
            def idx(*nombres):
                for nombre in nombres:
                    for i, cab in enumerate(cabeceras):
                        if nombre in cab:
                            return partes[i] if i < len(partes) else "-"
                return "-"

            # Validar IP con regex
            import re
            ip_raw    = idx("ip", "origen")
            ip_valida = bool(re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ip_raw.strip('`')))
            ip_final  = ip_raw.strip('`') if ip_valida else (ips_log[0] if ips_log else "-")

            amenazas.append({
                "numero"   : idx("linea", "número", "numero", "#"),
                "severidad": idx("severidad"),
                "tipo"     : idx("tipo"),
                "estado"   : idx("estado"),
                "ip"       : ip_final,
                "timestamp": obtener_timestamp_reporte(),
            })

        # Fin de tabla al encontrar otro heading
        if en_tabla and linea.startswith("##") and "AMENAZAS" not in linea.upper():
            en_tabla = False

    return amenazas


def extraer_ips_del_log() -> list[str]:
    """
    Extrae las IPs únicas del access.log ordenadas por frecuencia.
    La IP más frecuente es la más probable atacante.
    """
    from collections import Counter
    import re

    ruta = Path(LOG_PATH)
    if not ruta.exists():
        return []

    lineas = ruta.read_text(encoding="utf-8", errors="replace").splitlines()
    ips = []

    for linea in lineas:
        # La IP siempre es el primer campo en el log de Apache
        match = re.match(r'^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', linea)
        if match:
            ips.append(match.group(1))

    # Retornar IPs ordenadas por frecuencia (la más activa primero)
    contador = Counter(ips)
    return [ip for ip, _ in contador.most_common()]


def obtener_timeline_ataques() -> dict:
    """
    Analiza el log y agrupa los ataques sospechosos por hora.
    Retorna datos para el grafico de timeline.
    """
    import re
    from collections import defaultdict

    ruta = Path(LOG_PATH)
    if not ruta.exists():
        return {"horas": [], "counts": [], "tipos": {}}

    lineas = ruta.read_text(encoding="utf-8", errors="replace").splitlines()

    # Patrones de ataque para filtrar
    patrones = [
        "union", "select", "%27", "or+1", "or '1'",
        "<script", "%3cscript", "alert(",
        "../", "%2e%2e", "etc/passwd",
        "onerror", "onload"
    ]

    ataques_por_hora  = defaultdict(int)
    tipos_por_hora    = defaultdict(lambda: defaultdict(int))

    for linea in lineas:
        linea_lower = linea.lower()
        es_ataque   = any(p in linea_lower for p in patrones)
        if not es_ataque:
            continue

        # Extraer hora del timestamp Apache: [26/Apr/2026:20:43:28]
        match = re.search(r'\[(\d{2}/\w+/\d{4}):(\d{2}):', linea)
        if not match:
            continue

        fecha = match.group(1)  # 26/Apr/2026
        hora  = match.group(2)  # 20
        clave = f"{fecha} {hora}h"

        ataques_por_hora[clave] += 1

        # Clasificar tipo
        if any(p in linea_lower for p in ["union", "select", "%27", "or+1"]):
            tipos_por_hora[clave]["SQLi"] += 1
        if any(p in linea_lower for p in ["<script", "%3cscript", "alert("]):
            tipos_por_hora[clave]["XSS"] += 1
        if any(p in linea_lower for p in ["../", "%2e%2e", "etc/passwd"]):
            tipos_por_hora[clave]["Path Traversal"] += 1

    # Ordenar por clave temporal
    horas_ordenadas = sorted(ataques_por_hora.keys())

    return {
        "horas" : horas_ordenadas,
        "counts": [ataques_por_hora[h] for h in horas_ordenadas],
        "sqli"  : [tipos_por_hora[h].get("SQLi", 0) for h in horas_ordenadas],
        "xss"   : [tipos_por_hora[h].get("XSS", 0) for h in horas_ordenadas],
        "path"  : [tipos_por_hora[h].get("Path Traversal", 0) for h in horas_ordenadas],
    }


def obtener_timestamp_reporte() -> str:
    """Retorna la fecha de modificación del reporte actual."""
    ruta = REPORT_PATH / "reporte_seguridad.md"
    if ruta.exists():
        mtime = datetime.fromtimestamp(ruta.stat().st_mtime)
        return mtime.strftime("%d/%m %H:%M")
    return "--/-- --:--"


def obtener_estadisticas(amenazas: list[dict]) -> dict:
    """Calcula estadísticas resumen de las amenazas."""
    criticas = sum(1 for a in amenazas if "CRITICA" in a["severidad"].upper() or "CRÍTICA" in a["severidad"].upper())
    altas    = sum(1 for a in amenazas if "ALTA" in a["severidad"].upper())
    ips      = len(set(a["ip"] for a in amenazas if a["ip"] != "-"))

    return {
        "total"   : len(amenazas),
        "criticas": criticas,
        "altas"   : altas,
        "medias"  : len(amenazas) - criticas - altas,
        "ips"     : ips,
    }


def obtener_historial() -> list[dict]:
    """Lista los reportes históricos ordenados por fecha."""
    if not HISTORIAL.exists():
        return []

    archivos = sorted(HISTORIAL.glob("*.md"), reverse=True)[:10]
    historial = []

    for archivo in archivos:
        contenido = archivo.read_text(encoding="utf-8", errors="replace")
        amenazas  = parsear_amenazas(contenido)
        historial.append({
            "nombre"  : archivo.name,
            "amenazas": len(amenazas),
            "fecha"   : archivo.stem.split("_")[1] if "_" in archivo.stem else "-",
            "hora"    : archivo.stem.split("_")[2] if len(archivo.stem.split("_")) > 2 else "-",
        })

    return historial


def obtener_log_reciente() -> list[str]:
    """Retorna las últimas 8 líneas del log."""
    ruta = Path(LOG_PATH)
    if not ruta.exists():
        return ["Log no disponible"]
    lineas = ruta.read_text(encoding="utf-8", errors="replace").splitlines()
    return lineas[-8:] if lineas else []


# ============================================================
# RUTAS FLASK
# ============================================================

@app.route("/")
def index():
    """Página principal del dashboard."""
    reporte_path = REPORT_PATH / "reporte_seguridad.md"
    reporte      = ""
    amenazas     = []
    stats        = {"total": 0, "criticas": 0, "altas": 0, "medias": 0, "ips": 0}
    ultimo_ciclo = "Sin datos"

    if reporte_path.exists():
        reporte  = reporte_path.read_text(encoding="utf-8", errors="replace")
        amenazas = parsear_amenazas(reporte)
        stats    = obtener_estadisticas(amenazas)
        mtime    = datetime.fromtimestamp(reporte_path.stat().st_mtime)
        ultimo_ciclo = mtime.strftime("%d/%m/%Y %H:%M:%S")

    historial = obtener_historial()
    log_lines = obtener_log_reciente()

    return render_template(
        "index.html",
        amenazas     = amenazas,
        stats        = stats,
        historial    = historial,
        log_lines    = log_lines,
        ultimo_ciclo = ultimo_ciclo,
        reporte_md   = reporte,
        timeline     = obtener_timeline_ataques(),
    )


@app.route("/api/estado")
def api_estado():
    """API JSON con el estado actual — sincroniza el log antes de leer."""
    
    # Sincronizar log desde Docker automáticamente
    subprocess.run(
        ["docker", "cp", "dvwa-app:/var/log/apache2/access.log", LOG_PATH],
        capture_output=True, text=True
    )

    reporte_path = REPORT_PATH / "reporte_seguridad.md"
    amenazas     = []

    if reporte_path.exists():
        reporte  = reporte_path.read_text(encoding="utf-8", errors="replace")
        amenazas = parsear_amenazas(reporte)

    stats = obtener_estadisticas(amenazas)

    # IPs únicas del log real
    ips_log = extraer_ips_del_log()

    return jsonify({
        "stats"    : stats,
        "amenazas" : amenazas,
        "historial": obtener_historial(),
        "log"      : obtener_log_reciente(),
        "ips_log"  : ips_log[:5],  # Top 5 IPs más activas,
        "timeline" : obtener_timeline_ataques(),
        "timestamp": datetime.now().strftime("%d/%m/%Y %H:%M:%S"),
    })


@app.route("/api/sincronizar", methods=["POST"])
def api_sincronizar():
    """Sincroniza el log desde Docker y ejecuta el análisis."""
    try:
        # Paso 1: Sincronizar log
        sync = subprocess.run(
            ["docker", "cp", "dvwa-app:/var/log/apache2/access.log", LOG_PATH],
            capture_output=True, text=True
        )
        if sync.returncode != 0:
            return jsonify({"ok": False, "error": "Error sincronizando log"}), 500

        # Paso 2: Leer reporte, notificar y guardar historial
        reporte_path = REPORT_PATH / "reporte_seguridad.md"
        if reporte_path.exists():
            from config.notifications import notificar_alerta_critica
            from datetime import datetime

            reporte  = reporte_path.read_text(encoding="utf-8", errors="replace")
            amenazas = parsear_amenazas(reporte)

            # Guardar copia histórica
            timestamp     = datetime.now().strftime("%Y%m%d_%H%M%S")
            historial_dir = REPORT_PATH / "historial"
            historial_dir.mkdir(exist_ok=True)
            copia = historial_dir / f"reporte_{timestamp}.md"
            copia.write_text(reporte, encoding="utf-8")

            # Notificar amenazas críticas/altas
            alertas = [
                f"| {a['numero']} | {a['severidad']} | {a['tipo']} | {a['estado']} | {a['ip']} |"
                for a in amenazas
                if "CRITICA" in a["severidad"].upper() or "ALTA" in a["severidad"].upper()
            ]
            if alertas:
                notificar_alerta_critica(alertas, ciclo=1)

        return jsonify({"ok": True, "mensaje": "Analisis completado"})

    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500
    
@app.route("/report/<nombre>")
def ver_reporte(nombre):
    """Muestra un reporte histórico en formato legible."""
    import re
    # Acepta nombres como: reporte_20260427_133534.md
    if not re.match(r'^reporte_[\w]+\.md$', nombre):
        return f"Archivo no valido: {nombre}", 400

    ruta = HISTORIAL / nombre
    if not ruta.exists():
        ruta = REPORT_PATH / nombre
        if not ruta.exists():
            return f"Reporte no encontrado: {nombre}", 404

    contenido = ruta.read_text(encoding="utf-8", errors="replace")
    return render_template("report.html", contenido=contenido, nombre=nombre)


# ============================================================
# ARRANQUE
# ============================================================
if __name__ == "__main__":
    print("\n  T3r0S3c — Dashboard de Defensa Web")
    print("  Abre tu navegador en: http://localhost:5000\n")
    app.run(debug=True, host="0.0.0.0", port=5000)