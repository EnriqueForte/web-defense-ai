# agents/log_analyst.py
# ============================================================
# Módulo: Lector y procesador del access.log real de Apache
# ============================================================

import os
import time
from datetime import datetime
from pathlib import Path


# ============================================================
# CONFIGURACIÓN
# ============================================================

# Número máximo de líneas a analizar por ejecución.
# Evita enviar logs enormes al LLM (límite de tokens).
MAX_LINEAS = 30

# Patrones de ataque conocidos para pre-filtrar el log
# antes de enviarlo al LLM (ahorra tokens y tiempo).
PATRONES_SOSPECHOSOS = [
    # SQL Injection
    "union", "select", "insert", "drop", "delete", "update",
    "or+1=1", "or+%271", "%27", "1=1", "--", "/*", "*/",
    # XSS
    "<script", "alert(", "onerror=", "onload=", "javascript:",
    "<img", "<svg", "eval(", "document.cookie",
    "%3cscript", "%3c/script",
    # Path Traversal
    "../", "..%2f", "%2e%2e", "etc/passwd", "etc/shadow",
    "windows/system32",
    # Command Injection
    "/exec/", "vulnerabilities/exec",
    ";ls", ";cat", ";whoami", ";id", ";pwd",
    "&&whoami", "&&ls", "|whoami", "|ls",
    "%3bls", "%3bcat", "%3bwhoami",
    "%26%26", "%7ccat", "%7cls",
    # Fuerza Bruta
    "/brute/", "vulnerabilities/brute",
]


# ============================================================
# FUNCIONES PRINCIPALES
# ============================================================

def leer_log(ruta_log: str, max_lineas: int = MAX_LINEAS) -> list[str]:
    """
    Lee el archivo de log y retorna las últimas N líneas.
    
    Args:
        ruta_log: Ruta al archivo access.log
        max_lineas: Número máximo de líneas a retornar
    
    Returns:
        Lista de strings con cada línea del log
    """
    ruta = Path(ruta_log)
    
    # Verificar que el archivo existe
    if not ruta.exists():
        raise FileNotFoundError(
            f"No se encontró el log en: {ruta_log}\n"
            f"Verifica que el contenedor Docker está corriendo y "
            f"el volumen está montado correctamente."
        )
    
    # Verificar que el archivo no está vacío
    if ruta.stat().st_size == 0:
        print(f"⚠️  El archivo de log está vacío: {ruta_log}")
        return []
    
    # Leer las últimas N líneas del archivo
    with open(ruta, "r", encoding="utf-8", errors="replace") as f:
        lineas = f.readlines()
    
    # Retornar solo las últimas max_lineas
    return [linea.strip() for linea in lineas[-max_lineas:] if linea.strip()]


def pre_filtrar_lineas(lineas: list[str]) -> dict:
    """
    Pre-filtra las líneas del log buscando patrones sospechosos.
    Esto reduce el número de tokens enviados al LLM.
    
    Args:
        lineas: Lista de líneas del log
    
    Returns:
        Diccionario con líneas normales y sospechosas separadas
    """
    sospechosas = []
    normales = []
    
    for linea in lineas:
        linea_lower = linea.lower()
        
        # Verificar si la línea contiene algún patrón sospechoso
        es_sospechosa = any(
            patron in linea_lower 
            for patron in PATRONES_SOSPECHOSOS
        )
        
        if es_sospechosa:
            sospechosas.append(linea)
        else:
            normales.append(linea)
    
    return {
        "sospechosas": sospechosas,
        "normales": normales,
        "total": len(lineas),
        "porcentaje_sospechoso": round(
            len(sospechosas) / len(lineas) * 100, 2
        ) if lineas else 0
    }


def analizar_fuerza_bruta(lineas: list[str], 
                           umbral: int = 5, 
                           ventana_segundos: int = 60) -> list[str]:
    """
    Detecta posibles ataques de fuerza bruta analizando
    la frecuencia de peticiones POST al login desde una misma IP.
    
    Args:
        lineas: Lista de líneas del log
        umbral: Número de intentos para considerar fuerza bruta
        ventana_segundos: Ventana de tiempo en segundos
    
    Returns:
        Lista de líneas que forman parte de un posible ataque de fuerza bruta
    """
    from collections import defaultdict
    
    # Estructura: {ip: [(timestamp, linea), ...]}
    intentos_login = defaultdict(list)
    lineas_fuerza_bruta = []
    
    for linea in lineas:
        # Solo nos interesan los POST al login
        if "POST" in linea and "login" in linea.lower():
            partes = linea.split()
            if len(partes) < 4:
                continue
            
            ip = partes[0]
            
            # Extraer timestamp: [22/Apr/2026:10:17:01
            try:
                timestamp_str = partes[3].strip("[")
                timestamp = datetime.strptime(
                    timestamp_str, 
                    "%d/%b/%Y:%H:%M:%S"
                )
                intentos_login[ip].append((timestamp, linea))
            except (ValueError, IndexError):
                continue
    
    # Analizar frecuencia por IP
    for ip, intentos in intentos_login.items():
        if len(intentos) < umbral:
            continue
        
        # Ordenar por tiempo
        intentos.sort(key=lambda x: x[0])
        
        # Ventana deslizante para detectar ráfagas
        for i in range(len(intentos) - umbral + 1):
            tiempo_inicio = intentos[i][0]
            tiempo_fin = intentos[i + umbral - 1][0]
            diferencia = (tiempo_fin - tiempo_inicio).total_seconds()
            
            if diferencia <= ventana_segundos:
                # Encontrado patrón de fuerza bruta
                lineas_fb = [intento[1] for intento in intentos[i:i+umbral]]
                lineas_fuerza_bruta.extend(lineas_fb)
                break
    
    return list(set(lineas_fuerza_bruta))  # Eliminar duplicados


def preparar_log_para_agente(ruta_log: str) -> dict:
    """
    Lee y pre-procesa el log priorizando los ataques más críticos.
    Garantiza que Command Injection y Path Traversal siempre
    estén incluidos aunque haya muchas líneas de fuerza bruta.
    """
    print(f"📂 Leyendo log desde: {ruta_log}")

    lineas = leer_log(ruta_log, max_lineas=100)
    print(f"   → {len(lineas)} líneas leídas")

    if not lineas:
        return {"error": "Log vacío o no encontrado"}

    # Clasificar líneas por prioridad
    criticas   = []  # Command Injection, Path Traversal
    altas      = []  # SQLi, XSS
    otras      = []  # Fuerza Bruta y resto

    for linea in lineas:
        ll = linea.lower()

        es_cmd  = any(p in ll for p in ["/exec/", "%3b", "%7c", "%26%26"])
        es_path = any(p in ll for p in ["../", "%2e%2e", "etc/passwd"])
        es_sqli = any(p in ll for p in ["union", "select", "%27", "or+1"])
        es_xss  = any(p in ll for p in ["<script", "%3cscript", "alert("])
        es_fb   = any(p in ll for p in ["/brute/", "vulnerabilities/brute"])

        if es_cmd or es_path:
            criticas.append(linea)
        elif es_sqli or es_xss:
            altas.append(linea)
        elif es_fb:
            otras.append(linea)

    # Construir log balanceado para el agente:
    # - Todas las líneas críticas (Command Injection + Path Traversal)
    # - Hasta 5 líneas de SQLi/XSS
    # - Hasta 5 líneas de Fuerza Bruta (muestra del patrón)
    log_balanceado = criticas + altas[:5] + otras[:5]

    print(f"   → {len(criticas)} líneas críticas (Cmd/Path)")
    print(f"   → {len(altas[:5])} líneas altas (SQLi/XSS)")
    print(f"   → {len(otras[:5])} líneas otras (Fuerza Bruta)")

    fuerza_bruta = analizar_fuerza_bruta(lineas)

    contenido = "\n".join(log_balanceado) if log_balanceado else "\n".join(lineas[:30])

    filtrado = pre_filtrar_lineas(lineas)

    return {
        "contenido": contenido,
        "estadisticas": {
            "total_lineas"          : filtrado["total"],
            "lineas_sospechosas"    : len(filtrado["sospechosas"]),
            "porcentaje_sospechoso" : filtrado["porcentaje_sospechoso"],
            "fuerza_bruta_detectada": len(fuerza_bruta) > 0,
        },
        "timestamp_analisis": datetime.now().isoformat(),
    }