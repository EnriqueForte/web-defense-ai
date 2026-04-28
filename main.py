# main.py
# ============================================================
# Sistema de Defensa Web con Agentes de IA
# Versión: 1.0 · Fase 2
# ============================================================

import os
import sys
import time
import io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")
from dotenv import load_dotenv
from crewai import Agent, Task, Crew, Process, LLM
from config.prompts import PROMPT_ANALISTA


# Cargar variables de entorno desde .env
load_dotenv()

# ============================================================
# CONFIGURACIÓN DEL MODELO DE LENGUAJE
# ============================================================
def get_llm_con_retry():
    """
    Intenta inicializar el LLM con reintento si hay rate limit.
    """
    modelos = [
        "groq/meta-llama/llama-4-scout-17b-16e-instruct",
        "groq/llama-3.3-70b-versatile",
        "groq/llama-3.1-8b-instant",
    ]
    for modelo in modelos:
        try:
            llm = LLM(
                model=modelo,
                api_key=os.getenv("GROQ_API_KEY"),
                temperature=0.1,
            )
            print(f"   Modelo activo: {modelo}")
            return llm
        except Exception as e:
            print(f"   Modelo {modelo} no disponible, probando siguiente...")
            time.sleep(2)
            continue
    raise Exception("Ningun modelo disponible")


def get_llm():
    """
    Inicializa y retorna el modelo de lenguaje (LLM).
    Usamos llama-3.3-70b-versatile para análisis de seguridad
    porque necesitamos razonamiento preciso sobre patrones de ataque.
    Si quiero utilizar menos tokens utilizamos el modelo groq/llama-3.1-8b-instant (mas rápido menos tokens)
    """
    return LLM(
        model="groq/meta-llama/llama-4-scout-17b-16e-instruct",
        api_key=os.getenv("GROQ_API_KEY"),
        temperature=0.1,  # Baja temperatura = respuestas más precisas y consistentes
    )

# ============================================================
# DEFINICIÓN DE AGENTES
# Cada agente tiene un rol, objetivo y backstory específico.
# Esto guía al LLM para comportarse como un experto en ese dominio.
# ============================================================
def crear_agentes(llm):
    from agents.threat_detector  import crear_agente_detective
    from agents.report_generator import crear_agente_reporter

    agente_analista  = Agent(
        role="Analista de Logs de Seguridad",
        goal=(
            "Analizar logs de acceso web e identificar patrones "
            "sospechosos que puedan indicar ataques como SQLi, XSS, "
            "Path Traversal o fuerza bruta."
        ),
        backstory=PROMPT_ANALISTA,
        llm=llm,
        verbose=True,
        allow_delegation=False,
        max_iter=2,
    )

    agente_detective = crear_agente_detective(llm)
    agente_reporter  = crear_agente_reporter(llm)

    return agente_analista, agente_detective, agente_reporter


# ============================================================
# DEFINICIÓN DE TAREAS
# Cada tarea asigna trabajo concreto a un agente específico.
# ============================================================
def crear_tareas(agente_analista, agente_detective,
                 agente_reporter, contenido_log):
    from agents.threat_detector  import crear_tarea_clasificacion
    from agents.report_generator import crear_tarea_reporte

    tarea_analisis = Task(
        description=(
            f"Analiza el siguiente fragmento de access.log de Apache "
            f"e identifica TODAS las líneas que contengan patrones de ataque.\n\n"
            f"LOG A ANALIZAR:\n{contenido_log}\n\n"
            f"Para cada línea sospechosa indica:\n"
            f"1. La línea exacta del log\n"
            f"2. El tipo de ataque detectado\n"
            f"3. El indicador específico que te llevó a esa conclusión"
        ),
        expected_output=(
            "Lista estructurada de todas las líneas sospechosas con "
            "tipo de ataque e indicador de compromiso de cada una."
        ),
        agent=agente_analista,
    )

    tarea_clasificacion = crear_tarea_clasificacion(
        agente_detective, tarea_analisis
    )

    tarea_reporte = crear_tarea_reporte(
        agente_reporter, tarea_analisis, tarea_clasificacion
    )

    return tarea_analisis, tarea_clasificacion, tarea_reporte

# ============================================================
# FUNCIÓN PRINCIPAL
# ============================================================
def main():
    sys.stdout.reconfigure(encoding="utf-8")
    print("=" * 60)
    print("  🛡️  SISTEMA DE DEFENSA WEB CON AGENTES DE IA BY T3r0S3c")
    print("=" * 60)

    # ----------------------------------------------------------
    # PASO 1: Leer el log REAL de Apache desde el volumen Docker
    # ----------------------------------------------------------
    from agents.log_analyst import preparar_log_para_agente

    ruta_log = os.getenv("LOG_PATH", "./logs/access.log")
    
    resultado_lectura = preparar_log_para_agente(ruta_log)
    
    if "error" in resultado_lectura:
        print(f"❌ Error: {resultado_lectura['error']}")
        return
    
    stats = resultado_lectura["estadisticas"]
    contenido_log = resultado_lectura["contenido"]
    
    print(f"📊 Estadísticas del log:")
    print(f"   Total líneas analizadas : {stats['total_lineas']}")
    print(f"   Líneas sospechosas      : {stats['lineas_sospechosas']}")
    print(f"   Porcentaje sospechoso   : {stats['porcentaje_sospechoso']}%")
    print(f"   Fuerza bruta detectada  : {stats['fuerza_bruta_detectada']}")
    print()

    # ----------------------------------------------------------
    # PASO 2: Inicializar LLM y crear agentes
    # ----------------------------------------------------------
    llm = get_llm_con_retry()
    agente_analista, agente_detective, agente_reporter = crear_agentes(llm)

    # ----------------------------------------------------------
    # PASO 3: Crear tareas
    # ----------------------------------------------------------
    tarea_analisis, tarea_clasificacion, tarea_reporte = crear_tareas(
        agente_analista,
        agente_detective,
        agente_reporter,
        contenido_log
    )

    # ----------------------------------------------------------
    # PASO 4: Crear y ejecutar el Crew (equipo de agentes)
    # Process.sequential = los agentes trabajan en orden, uno tras otro
    # ----------------------------------------------------------
    crew = Crew(
        agents=[agente_analista, agente_detective, agente_reporter],
        tasks=[tarea_analisis, tarea_clasificacion, tarea_reporte],
        process=Process.sequential,  # Analista → Detective → Reporter
        verbose=True,
    )

    # ----------------------------------------------------------
    # PASO 5: Ejecutar el análisis
    # ----------------------------------------------------------
    print("🚀 Ejecutando análisis de seguridad...\n")
    resultado = crew.kickoff()

    # ----------------------------------------------------------
    # PASO 6: Guardar el reporte
    # ----------------------------------------------------------
    os.makedirs(os.getenv("REPORT_PATH", "./reports/"), exist_ok=True)
    ruta_reporte = os.path.join(
        os.getenv("REPORT_PATH", "./reports/"),
        "reporte_seguridad.md"
    )

    with open(ruta_reporte, "w", encoding="utf-8") as f:
        f.write(str(resultado))

    print("\n" + "=" * 60)
    print(f"  ✅ Reporte guardado en: {ruta_reporte}")
    print("=" * 60)


# ============================================================
# PUNTO DE ENTRADA
# ============================================================
if __name__ == "__main__":
    main()