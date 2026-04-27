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
MAX_LINEAS = 50

# Patrones de ataque conocidos para pre-filtrar el log
# antes de enviarlo al LLM (ahorra tokens y tiempo).
PATRONES_SOSPECHOSOS = [
    # SQL Injection
    "union", "select", "insert", "drop", "delete", "update",
    "or+1=1", "or '1'='1", "%27", "1=1", "--", "/*", "*/",
    # XSS
    "<script", "alert(", "onerror=", "onload=", "javascript:",
    "<img", "<svg", "eval(", "document.cookie",
    # Path Traversal
    "../", "..%2f", "%2e%2e", "etc/passwd", "etc/shadow",
    "windows/system32",
    # Fuerza Bruta (se detecta por frecuencia, no por patrón)
    # Se maneja en la función analizar_fuerza_bruta()
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
    Función principal que orquesta la lectura y pre-procesamiento
    del log para pasarlo al agente de IA.
    
    Args:
        ruta_log: Ruta al archivo access.log
    
    Returns:
        Diccionario con toda la información procesada lista para el agente
    """
    print(f"📂 Leyendo log desde: {ruta_log}")
    
    # 1. Leer el log
    lineas = leer_log(ruta_log)
    print(f"   → {len(lineas)} líneas leídas")
    
    if not lineas:
        return {"error": "Log vacío o no encontrado"}
    
    # 2. Pre-filtrar líneas sospechosas
    filtrado = pre_filtrar_lineas(lineas)
    print(f"   → {len(filtrado['sospechosas'])} líneas sospechosas "
          f"({filtrado['porcentaje_sospechoso']}%)")
    
    # 3. Detectar fuerza bruta
    fuerza_bruta = analizar_fuerza_bruta(lineas)
    if fuerza_bruta:
        print(f"   → ⚠️  {len(fuerza_bruta)} líneas de posible fuerza bruta")
    
    # 4. Combinar todas las líneas sospechosas sin duplicados
    todas_sospechosas = list(set(
        filtrado["sospechosas"] + fuerza_bruta
    ))
    
    # 5. Preparar el contenido final para el agente
    # Si hay líneas sospechosas, mandamos solo esas (más eficiente)
    # Si no hay, mandamos todas para que el agente decida
    contenido_para_agente = "\n".join(
        todas_sospechosas if todas_sospechosas else lineas
    )
    
    return {
        "contenido": contenido_para_agente,
        "estadisticas": {
            "total_lineas": filtrado["total"],
            "lineas_sospechosas": len(todas_sospechosas),
            "porcentaje_sospechoso": filtrado["porcentaje_sospechoso"],
            "fuerza_bruta_detectada": len(fuerza_bruta) > 0,
        },
        "timestamp_analisis": datetime.now().isoformat(),
    }