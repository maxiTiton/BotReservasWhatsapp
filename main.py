import os
import json
import time
import hmac
import hashlib
from datetime import datetime

import requests
import gspread
from dotenv import load_dotenv
from fastapi import FastAPI, Request, HTTPException, Response, Query

load_dotenv()

# Config desde .env
PHONE_NUMBER_ID = os.getenv("WHATSAPP_PHONE_NUMBER_ID")
ACCESS_TOKEN = os.getenv("WHATSAPP_ACCESS_TOKEN")
VERIFY_TOKEN = os.getenv("VERIFY_TOKEN")
APP_SECRET = os.getenv("APP_SECRET")          # usado para validar firma X-Hub-Signature-256
GOOGLE_CREDS = os.getenv("GOOGLE_CREDENTIALS_JSON", "credentials.json")
SHEET_NAME = os.getenv("SHEET_NAME", "ReservasBot")

# Iniciamos FastAPI
app = FastAPI(title="WhatsApp Reservations Bot - FastAPI MVP")

# In-memory session store (MVP). Para producción usar Redis / DB.
sessions = {}  # key = phone_number, value = {"state": str, "data": {...}, "last_ts": epoch}

# ---- Google Sheets: inicializar cliente ----
gc = gspread.service_account(filename=GOOGLE_CREDS)   # usa service account json
sheet = gc.open(SHEET_NAME).sheet1  # asume hoja 1; crear headers manualmente en la Sheet

# ---- Helpers ----
WHATSAPP_API_URL = f"https://graph.facebook.com/v17.0/{PHONE_NUMBER_ID}/messages"

def send_whatsapp_text(to_phone: str, text: str):
    """
    Envia un mensaje de texto via WhatsApp Cloud API.
    'to_phone' debe incluir prefijo internacional (ej: '5493511234567' para Arg.)
    """
    headers = {"Authorization": f"Bearer {ACCESS_TOKEN}", "Content-Type": "application/json"}
    payload = {
        "messaging_product": "whatsapp",
        "to": to_phone,
        "type": "text",
        "text": {"body": text}
    }
    r = requests.post(WHATSAPP_API_URL, headers=headers, json=payload)
    # opcional: chequear r.status_code y r.json() para log/errores
    return r

def verify_signature(raw_body: bytes, signature_header: str) -> bool:
    """
    Valida X-Hub-Signature-256: comparar HMAC SHA256(raw_body, APP_SECRET)
    signature_header viene como 'sha256=HEX...'
    """
    if not APP_SECRET or not signature_header:
        return False
    try:
        expected = hmac.new(APP_SECRET.encode('utf-8'), raw_body, hashlib.sha256).hexdigest()
        received = signature_header.replace("sha256=", "")
        return hmac.compare_digest(expected, received)
    except Exception:
        return False

def start_reservation_flow(from_phone: str):
    sessions[from_phone] = {"state": "awaiting_name", "data": {}, "last_ts": time.time()}
    send_whatsapp_text(from_phone, "Perfecto. Para reservar, ¿cómo te llamás?")

def save_reservation_to_sheet(phone, name, date_str, time_str, note=""):
    ts = datetime.utcnow().isoformat()
    row = [ts, phone, name, date_str, time_str, note]
    sheet.append_row(row)

# ---- Webhook verification endpoint (GET) ----
@app.get("/webhook")
async def webhook_verify(
    hub_mode: str = Query(None, alias="hub.mode"),
    hub_challenge: str = Query(None, alias="hub.challenge"),
    hub_verify_token: str = Query(None, alias="hub.verify_token")
):
    if hub_verify_token == VERIFY_TOKEN:
        return Response(content=hub_challenge, media_type="text/plain")
    else:
        raise HTTPException(status_code=403, detail="Verify token mismatch")
    

# ---- Webhook receiver (POST) ----
@app.post("/webhook")
async def webhook_receiver(request: Request):
    raw_body = await request.body()
    signature = request.headers.get("X-Hub-Signature-256", "")
    # Verificamos firma (recomendado en producción)
    if not verify_signature(raw_body, signature):
        # Si estás en desarrollo con ngrok, podés desactivar la verificación (NO en producción).
        # raise HTTPException(status_code=401, detail="Firma inválida")
        pass  # para dev, evitar bloquear. En producción, activar la línea anterior.

    payload = json.loads(raw_body.decode("utf-8"))
    # payload tiene esta estructura: entry -> changes -> value -> messages
    # (ver ejemplos en la documentación oficial)
    try:
        entries = payload.get("entry", [])
        for entry in entries:
            changes = entry.get("changes", [])
            for change in changes:
                value = change.get("value", {})
                messages = value.get("messages", [])
                if not messages:
                    continue
                for msg in messages:
                    from_phone = msg.get("from")  # número del usuario
                    msg_type = msg.get("type")
                    text_body = None
                    if msg_type == "text":
                        text_body = msg.get("text", {}).get("body", "")
                    else:
                        # manejar otros tipos si querés (interactive, button, etc)
                        text_body = "[no-text-message]"

                    # Process simple reservation flow
                    session = sessions.get(from_phone)
                    text_lower = (text_body or "").strip().lower()

                    if session is None:
                        # decide si arrancar flujo de reserva o responder FAQ - Frequently Asked Questions
                        if "reserv" in text_lower or "turn" in text_lower or "reserva" in text_lower:
                            start_reservation_flow(from_phone)
                        else:
                            # Respuesta simple: pedir que indique si quiere reservar
                            send_whatsapp_text(from_phone, "Hola 👋. ¿Querés reservar? Escribí 'Reservar' para comenzar.")
                    else:
                        state = session["state"]
                        if state == "awaiting_name":
                            session["data"]["name"] = text_body.strip()
                            session["state"] = "awaiting_date"
                            send_whatsapp_text(from_phone, "Perfecto, ¿qué fecha querés? (ej: 2025-10-10)")
                        elif state == "awaiting_date":
                            session["data"]["date"] = text_body.strip()
                            session["state"] = "awaiting_time"
                            send_whatsapp_text(from_phone, "¿A qué hora? (ej: 20:00)")
                        elif state == "awaiting_time":
                            session["data"]["time"] = text_body.strip()
                            # Guardar en Google Sheets
                            name = session["data"].get("name", "")
                            date_s = session["data"].get("date", "")
                            time_s = session["data"].get("time", "")
                            save_reservation_to_sheet(from_phone, name, date_s, time_s)
                            send_whatsapp_text(from_phone, f"¡Listo {name}! Tu reserva para {date_s} a las {time_s} quedó registrada ✅")
                            # Notificar al dueño (ej: acá podés enviar un mail o un mensaje interno)
                            sessions.pop(from_phone, None)
                        else:
                            send_whatsapp_text(from_phone, "Perdón, no te entendí. Escribí 'Reservar' para empezar.")
    except Exception as e:
        # log error
        print("Webhook process error:", e)

    return {"status": "received"}
