# config/settings.py
# ============================================================
# Configuración global del Sistema de Defensa Web
# ============================================================

import os
from dotenv import load_dotenv

load_dotenv()

# --- Rutas ---
LOG_PATH        = os.getenv("LOG_PATH", "./logs/access.log")
REPORT_PATH     = os.getenv("REPORT_PATH", "./reports/")

# --- LLM ---
GROQ_API_KEY    = os.getenv("GROQ_API_KEY")
LLM_MODEL = os.getenv("LLM_MODEL", "groq/meta-llama/llama-4-scout-17b-16e-instruct")
LLM_TEMPERATURE = float(os.getenv("LLM_TEMPERATURE", "0.1"))

# --- Pipeline ---
INTERVALO_MINUTOS   = int(os.getenv("INTERVALO_MINUTOS", "3"))
MAX_LINEAS_LOG      = int(os.getenv("MAX_LINEAS_LOG", "100"))
UMBRAL_FUERZA_BRUTA = int(os.getenv("UMBRAL_FUERZA_BRUTA", "5"))

# --- Alertas ---
# Severidades que disparan alerta inmediata en consola
SEVERIDADES_CRITICAS = ["CRÍTICA", "ALTA"]