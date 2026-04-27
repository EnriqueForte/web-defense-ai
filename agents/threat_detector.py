# agents/threat_detector.py
# ============================================================
# Agente 2: Detective de Amenazas
# Responsabilidad: Clasificar y priorizar amenazas detectadas
# ============================================================

from crewai import Agent, Task
from config.prompts import PROMPT_DETECTIVE


def crear_agente_detective(llm) -> Agent:
    """
    Crea el agente Detective de Amenazas.
    Recibe el análisis del Agente 1 y clasifica cada amenaza
    según severidad, tipo y estado.
    """
    return Agent(
        role="Detective de Amenazas Cibernéticas",
        goal=(
            "Clasificar las amenazas identificadas por el Analista según "
            "su severidad (CRÍTICA, ALTA, MEDIA, BAJA) y determinar "
            "si representan un ataque activo o un falso positivo."
        ),
        backstory=PROMPT_DETECTIVE,
        llm=llm,
        verbose=True,
        allow_delegation=False,
        max_iter=2,
    )


def crear_tarea_clasificacion(agente_detective, tarea_analisis) -> Task:
    """
    Crea la tarea de clasificación de amenazas.
    Recibe el output del Agente 1 como contexto.
    """
    return Task(
        description=(
            "Basándote en el análisis previo del Analista de Logs, "
            "clasifica cada amenaza detectada según:\n"
            "- Severidad: CRÍTICA / ALTA / MEDIA / BAJA\n"
            "- Tipo de ataque: SQLi / XSS / Path Traversal / Fuerza Bruta / Otro\n"
            "- Estado: ATAQUE ACTIVO / FALSO POSITIVO / REQUIERE INVESTIGACIÓN\n"
            "- IP origen del atacante si está disponible\n\n"
            "Sigue estrictamente los criterios de severidad de tu backstory."
        ),
        expected_output=(
            "Tabla Markdown con columnas: "
            "Línea | Severidad | Tipo de Ataque | Estado | IP Origen. "
            "Una fila por cada amenaza detectada."
        ),
        agent=agente_detective,
        context=[tarea_analisis],
    )