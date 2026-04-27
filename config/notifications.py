# config/notificaciones.py
import smtplib
import os
import requests
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from dotenv import load_dotenv

load_dotenv()

def enviar_telegram(mensaje: str) -> bool:
    token   = os.getenv("TELEGRAM_BOT_TOKEN")
    chat_id = os.getenv("TELEGRAM_CHAT_ID")
    if not token or not chat_id:
        print("Telegram no configurado en .env")
        return False
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    payload = {"chat_id": chat_id, "text": mensaje, "parse_mode": "HTML"}
    try:
        r = requests.post(url, json=payload, timeout=10)
        if r.status_code == 200:
            print("✅ Alerta enviada por Telegram")
            return True
        print(f"❌ Error Telegram: {r.text}")
        return False
    except Exception as e:
        print(f"❌ Error Telegram: {e}")
        return False

def enviar_email(asunto: str, cuerpo: str) -> bool:
    remitente    = os.getenv("EMAIL_REMITENTE")
    password     = os.getenv("EMAIL_PASSWORD", "").replace(" ", "")
    destinatario = os.getenv("EMAIL_DESTINATARIO")
    smtp_server  = os.getenv("EMAIL_SMTP_SERVER", "smtp.gmail.com")
    smtp_port    = int(os.getenv("EMAIL_SMTP_PORT", "587"))
    if not all([remitente, password, destinatario]):
        print("Email no configurado en .env")
        return False
    msg = MIMEMultipart()
    msg["Subject"] = asunto
    msg["From"]    = remitente
    msg["To"]      = destinatario
    msg.attach(MIMEText(cuerpo, "plain", "utf-8"))
    try:
        with smtplib.SMTP(smtp_server, smtp_port) as s:
            s.starttls()
            s.login(remitente, password)
            s.sendmail(remitente, destinatario, msg.as_string())
        print(f"✅ Alerta enviada por email a {destinatario}")
        return True
    except Exception as e:
        print(f"❌ Error email: {e}")
        return False

def notificar_alerta_critica(alertas: list, ciclo: int) -> None:
    if not alertas:
        return
    from datetime import datetime
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    criticas = [a for a in alertas if "CRITICA" in a.upper()]
    altas    = [a for a in alertas if "ALTA" in a.upper()]
    mensaje_telegram = (
        f"🚨 <b>ALERTA DE SEGURIDAD - T3r0S3c</b>\n\n"
        f"Timestamp: {timestamp}\n"
        f"Ciclo: #{ciclo}\n\n"
        f"CRITICAS : {len(criticas)}\n"
        f"ALTAS    : {len(altas)}\n\n"
        f"<b>Detalle:</b>\n"
    )
    for alerta in alertas[:5]:
        # Extraer solo campos clave de la línea de tabla
        partes = [p.strip() for p in alerta.split("|") if p.strip()]
        if len(partes) >= 4:
            num       = partes[0]
            severidad = partes[1]
            tipo      = partes[2]
            estado    = partes[3]
            ip        = partes[4] if len(partes) > 4 else "-"
            mensaje_telegram += f"  [{num}] {severidad} — {tipo} — {ip}\n"
        else:
            mensaje_telegram += f"  {alerta[:80]}\n"
            
    mensaje_email = (
        f"ALERTA DE SEGURIDAD - T3r0S3c\n"
        f"{'='*50}\n"
        f"Timestamp : {timestamp}\n"
        f"Ciclo     : #{ciclo}\n"
        f"CRITICAS  : {len(criticas)}\n"
        f"ALTAS     : {len(altas)}\n\n"
        f"DETALLE:\n" + "\n".join(alertas)
    )
    enviar_telegram(mensaje_telegram)
    enviar_email(
        asunto=f"[ALERTA T3r0S3c] {len(criticas)} amenazas CRITICAS detectadas",
        cuerpo=mensaje_email
    )