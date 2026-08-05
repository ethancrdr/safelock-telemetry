from fastapi import FastAPI, Header, HTTPException, Depends, Request
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from pydantic import BaseModel
from datetime import datetime, timedelta, timezone
from contextlib import asynccontextmanager
from typing import Any, Dict, List, Optional
import hashlib
import os
import re
import httpx
import secrets
from dotenv import load_dotenv

load_dotenv()


@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.http = httpx.AsyncClient(timeout=20.0)
    yield
    await app.state.http.aclose()


app = FastAPI(title="SafeLock Telemetry SOC", lifespan=lifespan)

API_SECRET = os.environ.get("API_SECRET", "openlock2026")
SUPABASE_URL = os.environ.get("SUPABASE_URL")
SUPABASE_KEY = os.environ.get("SUPABASE_KEY")

# --- Configuración OTA ---
# Token que usa GitHub Actions para registrar un release nuevo.
OTA_ADMIN_TOKEN = os.environ.get("OTA_ADMIN_TOKEN", "")

# Secreto de arranque: solo sirve para que un dispositivo se enrole una vez y
# reciba su secreto propio. Se cierra (ENROLLMENT_OPEN=false) al terminar la
# migración de la flota.
ENROLLMENT_SECRET = os.environ.get("ENROLLMENT_SECRET", API_SECRET)
ENROLLMENT_OPEN = os.environ.get("ENROLLMENT_OPEN", "true").lower() == "true"

# Mientras haya equipos sin migrar siguen llegando heartbeats con el secreto
# compartido antiguo. Se apaga cuando el dashboard muestre 100% migrado.
LEGACY_SECRET_ENABLED = os.environ.get("LEGACY_SECRET_ENABLED", "true").lower() == "true"

# Contraseña del dashboard, separada del secreto de los dispositivos para poder
# rotar una sin tocar la otra.
DASHBOARD_PASSWORD = os.environ.get("DASHBOARD_PASSWORD", API_SECRET)

# El repositorio es privado, asi que los equipos no pueden descargar los assets
# de GitHub Releases. El CI los sube aqui al publicar un tag y este servidor se
# los sirve a cada dispositivo autenticado. Sigue siendo solo transporte: la
# firma RSA se verifica en el equipo, asi que un servidor comprometido no puede
# instalar codigo que no venga firmado con la clave OTA.
ARTIFACT_DIR = os.environ.get("ARTIFACT_DIR", "/var/lib/safelock/releases")
MAX_ARTIFACT_BYTES = 300 * 1024 * 1024
NOMBRE_SEGURO = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")

# Credenciales SMTP que los dispositivos descargan en /etc/safelock/env.
DEVICE_SMTP = {
    "SMTP_SERVER": os.environ.get("SMTP_SERVER", ""),
    "SMTP_PORT": os.environ.get("SMTP_PORT", "587"),
    "SMTP_SENDER": os.environ.get("SMTP_SENDER", ""),
    "SMTP_PASSWORD": os.environ.get("SMTP_PASSWORD", ""),
}

security = HTTPBasic()


def hash_secret(valor: str) -> str:
    return hashlib.sha256(valor.encode("utf-8")).hexdigest()


# --- Acceso a Supabase ---
def sb_client() -> httpx.AsyncClient:
    """Cliente compartido creado en el lifespan. Abrir uno por petición hacía
    crecer la memoria del proceso sin límite (commit 35c5c0f)."""
    return app.state.http


async def sb_get(path: str):
    return await sb_client().get(f"{SUPABASE_URL}/rest/v1/{path}", headers=sb_headers())


async def sb_post(path: str, payload):
    return await sb_client().post(f"{SUPABASE_URL}/rest/v1/{path}",
                                  headers=sb_headers(), json=payload)


async def sb_rows(path: str) -> List[Dict[str, Any]]:
    r = await sb_get(path)
    if r.status_code != 200:
        return []
    data = r.json()
    return data if isinstance(data, list) else []


def sb_headers():
    if not SUPABASE_KEY:
        raise HTTPException(status_code=500, detail="SUPABASE_KEY no está configurada")

    return {
        "apikey": SUPABASE_KEY,
        "Authorization": f"Bearer {SUPABASE_KEY}",
        "Content-Type": "application/json",
        "Prefer": "resolution=merge-duplicates"
    }


def require_supabase():
    if not SUPABASE_URL:
        raise HTTPException(status_code=500, detail="SUPABASE_URL no está configurada")
    if not SUPABASE_KEY:
        raise HTTPException(status_code=500, detail="SUPABASE_KEY no está configurada")


# --- Seguridad ---
def verificar_acceso_dashboard(credentials: HTTPBasicCredentials = Depends(security)):
    usuario_correcto = secrets.compare_digest(credentials.username, "admin")
    clave_correcta = secrets.compare_digest(credentials.password, DASHBOARD_PASSWORD)

    if not (usuario_correcto and clave_correcta):
        raise HTTPException(
            status_code=401,
            detail="Acceso denegado a la Telemetría",
            headers={"WWW-Authenticate": "Basic"},
        )

    return credentials.username


# --- MODELOS ---
class Heartbeat(BaseModel):
    device_id: str
    pihole_active: bool = False
    tailscale_ip: str = ""
    version: str = "1.0"
    commit: str = ""
    critical_alert: bool = False
    # Enviados por el agente OTA nuevo; ausentes en los equipos sin migrar.
    ota: Optional[Dict[str, Any]] = None
    health: Optional[Dict[str, Any]] = None
    # Enviado por el heartbeat.sh antiguo durante la migración.
    migration_state: str = ""


class DeviceMetadataUpdate(BaseModel):
    display_name: str = ""
    label: str = ""


class EnrollRequest(BaseModel):
    device_id: str
    secret: str


class ReleaseRequest(BaseModel):
    tag: str
    notes: str = ""


class PromoteRequest(BaseModel):
    tag: str
    channel: str = "stable"


class PauseRequest(BaseModel):
    paused: bool = True
    channel: str = "stable"


# --- Autenticación de dispositivos ---
async def autenticar_dispositivo(
    x_device_id: Optional[str] = Header(None),
    x_device_secret: Optional[str] = Header(None),
    x_api_secret: Optional[str] = Header(None),
) -> str:
    """Secreto propio del dispositivo; el compartido antiguo solo mientras dure
    la migración."""
    require_supabase()

    if x_device_id and x_device_secret:
        filas = await sb_rows(f"devices?device_id=eq.{x_device_id}&select=secret_hash")
        guardado = (filas[0].get("secret_hash") if filas else None) or ""
        if guardado and secrets.compare_digest(guardado, hash_secret(x_device_secret)):
            return x_device_id

    if LEGACY_SECRET_ENABLED and x_api_secret and secrets.compare_digest(x_api_secret, API_SECRET):
        return x_device_id or ""

    raise HTTPException(status_code=401, detail="Dispositivo no autorizado")


def verificar_admin(x_admin_token: Optional[str] = Header(None)) -> bool:
    if not OTA_ADMIN_TOKEN:
        raise HTTPException(status_code=503, detail="OTA_ADMIN_TOKEN no está configurado")
    if not (x_admin_token and secrets.compare_digest(x_admin_token, OTA_ADMIN_TOKEN)):
        raise HTTPException(status_code=401, detail="Token de administración inválido")
    return True


# --- HEARTBEAT ---
@app.post("/heartbeat")
async def heartbeat(
    data: Heartbeat,
    autenticado: str = Depends(autenticar_dispositivo),
):
    # Un dispositivo autenticado con su secreto propio solo puede reportar
    # sobre sí mismo.
    if autenticado and autenticado != data.device_id:
        raise HTTPException(status_code=403, detail="device_id no coincide con la credencial")

    ota = data.ota or {}
    payload = {
        "device_id": data.device_id,
        "pihole_active": data.pihole_active,
        "version": data.version,
        "commit_sha": data.commit,
        "critical_alert": data.critical_alert,
        "ota_state": ota.get("state", ""),
        "ota_error": (ota.get("last_error") or "")[:500],
        "ota": ota,
        "health": data.health or {},
        "last_seen": datetime.now(timezone.utc).isoformat(),
        "status": "online",
    }
    # Si el agente no logra leer su IP en este ciclo (tailscaled aún no
    # arriba, blip de red) manda "". No pisar la última IP buena conocida.
    if data.tailscale_ip:
        payload["tailscale_ip"] = data.tailscale_ip
    if data.migration_state:
        payload["migration_state"] = data.migration_state

    r = await sb_post("devices?on_conflict=device_id", payload)
    if r.status_code not in [200, 201, 204]:
        raise HTTPException(status_code=500, detail=f"Error guardando heartbeat en Supabase: {r.text}")

    return {"ok": True}


# --- ENROLAMIENTO ---
@app.post("/api/enroll")
async def enroll(data: EnrollRequest, x_api_secret: Optional[str] = Header(None)):
    """Un dispositivo cambia el secreto compartido por uno propio, una sola vez."""
    require_supabase()

    if not ENROLLMENT_OPEN:
        raise HTTPException(status_code=403, detail="El enrolamiento está cerrado")

    if not (x_api_secret and secrets.compare_digest(x_api_secret, ENROLLMENT_SECRET)):
        raise HTTPException(status_code=401, detail="Secreto de enrolamiento inválido")

    filas = await sb_rows(f"devices?device_id=eq.{data.device_id}&select=secret_hash")
    if filas and filas[0].get("secret_hash"):
        # Ya tiene secreto: reenrolar permitiría suplantarlo desde fuera.
        raise HTTPException(status_code=409, detail="El dispositivo ya está enrolado")

    r = await sb_post("devices?on_conflict=device_id", {
        "device_id": data.device_id,
        "secret_hash": hash_secret(data.secret),
        "enrolled_at": datetime.now(timezone.utc).isoformat(),
    })
    if r.status_code not in [200, 201, 204]:
        raise HTTPException(status_code=500, detail=f"Error enrolando: {r.text}")

    return {"ok": True, "device_id": data.device_id}


# --- OBJETIVO OTA ---
@app.get("/api/ota/target")
async def ota_target(device_id: str = Depends(autenticar_dispositivo)):
    """Qué versión le toca a este dispositivo según su canal."""
    canal = "stable"
    if device_id:
        filas = await sb_rows(f"devices?device_id=eq.{device_id}&select=channel")
        if filas and filas[0].get("channel"):
            canal = filas[0]["channel"]

    objetivos = await sb_rows(f"ota_targets?channel=eq.{canal}&select=tag,paused")
    if not objetivos:
        return {"tag": None, "paused": False, "channel": canal}

    return {
        "tag": objetivos[0].get("tag"),
        "paused": bool(objetivos[0].get("paused")),
        "channel": canal,
    }


# --- ARTEFACTOS DE RELEASE ---
def ruta_artefacto(tag: str, nombre: str) -> str:
    """Ruta en disco de un asset, rechazando cualquier intento de salir de
    ARTIFACT_DIR (tag y nombre llegan de la URL)."""
    if not (NOMBRE_SEGURO.match(tag) and NOMBRE_SEGURO.match(nombre)):
        raise HTTPException(status_code=400, detail="Nombre de artefacto inválido")

    base = os.path.abspath(ARTIFACT_DIR)
    destino = os.path.abspath(os.path.join(base, tag, nombre))
    if not destino.startswith(base + os.sep):
        raise HTTPException(status_code=400, detail="Ruta de artefacto inválida")
    return destino


@app.put("/api/ota/artifact/{tag}/{nombre}")
async def subir_artefacto(
    tag: str,
    nombre: str,
    request: Request,
    _: bool = Depends(verificar_admin),
):
    """La sube GitHub Actions al publicar. Se escribe a .tmp y se renombra para
    que un corte a mitad no deje un artefacto truncado servible."""
    destino = ruta_artefacto(tag, nombre)
    os.makedirs(os.path.dirname(destino), exist_ok=True)
    tmp = destino + ".tmp"

    total = 0
    try:
        with open(tmp, "wb") as f:
            async for chunk in request.stream():
                total += len(chunk)
                if total > MAX_ARTIFACT_BYTES:
                    raise HTTPException(status_code=413, detail="Artefacto demasiado grande")
                f.write(chunk)
        os.replace(tmp, destino)
    except Exception:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise

    return {"ok": True, "tag": tag, "name": nombre, "size": total}


@app.get("/api/ota/artifact/{tag}/{nombre}")
async def descargar_artefacto(
    tag: str,
    nombre: str,
    device_id: str = Depends(autenticar_dispositivo),
):
    ruta = ruta_artefacto(tag, nombre)
    if not os.path.isfile(ruta):
        raise HTTPException(status_code=404, detail=f"No existe {nombre} para {tag}")
    return FileResponse(ruta, media_type="application/octet-stream", filename=nombre)


# --- CONFIGURACIÓN QUE BAJA EL DISPOSITIVO ---
@app.get("/api/device-config")
async def device_config(device_id: str = Depends(autenticar_dispositivo)):
    return {"smtp": DEVICE_SMTP}


# --- REGISTRO Y PROMOCIÓN DE RELEASES ---
@app.post("/api/ota/releases")
async def registrar_release(data: ReleaseRequest, _: bool = Depends(verificar_admin)):
    """Lo llama GitHub Actions al publicar un tag. Entra siempre por canary."""
    require_supabase()
    ahora = datetime.now(timezone.utc).isoformat()

    r = await sb_post("ota_releases?on_conflict=tag", {
        "tag": data.tag,
        "created_at": ahora,
        "status": "canary",
        "notes": data.notes,
    })
    if r.status_code not in [200, 201, 204]:
        raise HTTPException(status_code=500, detail=f"Error registrando release: {r.text}")

    await sb_post("ota_targets?on_conflict=channel", {
        "channel": "canary",
        "tag": data.tag,
        "paused": False,
        "updated_at": ahora,
    })
    return {"ok": True, "tag": data.tag, "channel": "canary"}


@app.post("/api/ota/promote")
async def promover_release(
    data: PromoteRequest,
    username: str = Depends(verificar_acceso_dashboard),
):
    """Promueve un tag al canal indicado (por defecto stable = toda la flota)."""
    require_supabase()
    ahora = datetime.now(timezone.utc).isoformat()

    releases = await sb_rows(f"ota_releases?tag=eq.{data.tag}&select=tag")
    if not releases:
        raise HTTPException(status_code=404, detail=f"El release {data.tag} no está registrado")

    r = await sb_post("ota_targets?on_conflict=channel", {
        "channel": data.channel,
        "tag": data.tag,
        "paused": False,
        "updated_at": ahora,
    })
    if r.status_code not in [200, 201, 204]:
        raise HTTPException(status_code=500, detail=f"Error promoviendo: {r.text}")

    if data.channel == "stable":
        await sb_post("ota_releases?on_conflict=tag",
                      {"tag": data.tag, "status": "stable"})

    return {"ok": True, "tag": data.tag, "channel": data.channel}


@app.post("/api/ota/pause")
async def pausar_rollout(
    data: PauseRequest,
    username: str = Depends(verificar_acceso_dashboard),
):
    """Congela el rollout sin revertir nada: los equipos se quedan donde están."""
    require_supabase()
    objetivos = await sb_rows(f"ota_targets?channel=eq.{data.channel}&select=tag")
    tag = objetivos[0].get("tag") if objetivos else None

    r = await sb_post("ota_targets?on_conflict=channel", {
        "channel": data.channel,
        "tag": tag,
        "paused": data.paused,
        "updated_at": datetime.now(timezone.utc).isoformat(),
    })
    if r.status_code not in [200, 201, 204]:
        raise HTTPException(status_code=500, detail=f"Error pausando: {r.text}")

    return {"ok": True, "channel": data.channel, "paused": data.paused}


@app.get("/api/ota/status")
async def estado_rollout(username: str = Depends(verificar_acceso_dashboard)):
    """Resumen del rollout para el dashboard."""
    require_supabase()
    objetivos = await sb_rows("ota_targets?select=channel,tag,paused,updated_at")
    releases = await sb_rows("ota_releases?select=tag,status,created_at&order=created_at.desc&limit=10")
    return {
        "targets": {o["channel"]: o for o in objetivos if o.get("channel")},
        "releases": releases,
    }


# --- FLEET ---
@app.get("/api/fleet")
async def get_fleet_data(username: str = Depends(verificar_acceso_dashboard)):
    require_supabase()

    campos = ("device_id,pihole_active,tailscale_ip,last_seen,version,critical_alert,"
              "display_name,label,commit_sha,channel,ota_state,ota,health,migration_state")

    r = await sb_get(f"devices?select={campos}&limit=500")

    if r.status_code != 200:
        raise HTTPException(status_code=500, detail=f"Error de Supabase: {r.text}")

    rows = r.json()
    now = datetime.now(timezone.utc)
    valid_rows = []

    # Versión objetivo, para poder marcar quién está al día y quién no.
    objetivos = await sb_rows("ota_targets?select=channel,tag,paused")
    targets = {o["channel"]: o for o in objetivos if o.get("channel")}

    for d in rows:
        last_seen_str = d.get("last_seen")
        if not last_seen_str:
            continue

        try:
            last = datetime.fromisoformat(last_seen_str.replace("Z", "+00:00"))
            if last.tzinfo is None:
                last = last.replace(tzinfo=timezone.utc)

            is_online = (now - last) < timedelta(minutes=15)
            d["status"] = "online" if is_online else "offline"

            ago = now - last
            mins = int(ago.total_seconds() / 60)
            d["time_ago"] = f"hace {mins}m" if mins < 60 else f"hace {mins // 60}h"
            d["critical_alert"] = d.get("critical_alert", False)
            d["display_name"] = d.get("display_name", "")
            d["label"] = d.get("label", "")

            canal = d.get("channel") or "stable"
            objetivo = (targets.get(canal) or {}).get("tag")
            d["channel"] = canal
            d["target_version"] = objetivo
            d["up_to_date"] = bool(objetivo) and d.get("version") == objetivo
            d["ota_state"] = d.get("ota_state") or ""
            d["migrated"] = bool(d.get("ota"))

            valid_rows.append(d)

        except ValueError:
            continue

    return {"devices": valid_rows, "targets": targets}


# --- AUTH CHECK ---
@app.get("/api/auth-check")
async def auth_check(username: str = Depends(verificar_acceso_dashboard)):
    return {"ok": True, "user": username}


# --- UPDATE METADATA (Supabase) ---
@app.post("/api/device-metadata/{device_id}")
async def update_device_metadata(
    request: Request,
    device_id: str,
    data: DeviceMetadataUpdate,
    username: str = Depends(verificar_acceso_dashboard),
):
    require_supabase()

    payload = {
        "device_id": device_id,
        "display_name": data.display_name.strip(),
        "label": data.label.strip(),
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }

    client = request.app.state.http
    r = await client.post(
        f"{SUPABASE_URL}/rest/v1/devices?on_conflict=device_id",
        headers=sb_headers(),
        json=payload
    )

    if r.status_code not in [200, 201, 204]:
        raise HTTPException(
            status_code=500,
            detail=f"Error guardando en Supabase: {r.text}"
        )

    return {"ok": True, "device_id": device_id, "metadata": payload}


# --- DASHBOARD HTML/JS ---
@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard_ui():
    html_content = """<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="utf-8">
    <title>SafeLock SOC Telemetry</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        @import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@400;500;600&family=IBM+Plex+Mono:wght@400;600;700&display=swap');
        body { background: #050608; color: #D1D5DB; font-family: 'IBM Plex Sans', sans-serif; padding: 0; margin: 0; }
        * { box-sizing: border-box; }

        #login-view { height: 100vh; display: flex; align-items: center; justify-content: center; }
        .login-box { background: #121417; padding: 40px; border-radius: 12px; border: 1px solid #333; width: 100%; max-width: 360px; text-align: center; box-shadow: 0 0 40px rgba(41,181,181,0.1); }
        .login-box h2 { color: #29B5B5; font-family: 'IBM Plex Mono', monospace; font-size: 20px; margin-bottom: 8px; }
        .login-box p { color: #6B7280; font-size: 13px; margin-bottom: 24px; }
        .login-box input { width: 100%; padding: 12px; margin-bottom: 16px; background: #08090A; border: 1px solid #333; color: #fff; border-radius: 6px; outline: none; font-family: 'IBM Plex Mono', monospace; }
        .login-box input:focus { border-color: #29B5B5; }
        .login-box button { width: 100%; padding: 14px; background: #29B5B5; color: #000; border: none; border-radius: 6px; font-weight: bold; cursor: pointer; font-family: 'IBM Plex Mono', monospace; text-transform: uppercase; }
        .error-msg { color: #EF4444; font-size: 12px; margin-top: 12px; display: none; }

        #dashboard-view { display: none; padding: 32px; max-width: 1200px; margin: 0 auto; }
        .header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 32px; }
        h1 { color: #29B5B5; font-size: 24px; margin: 0; font-family: 'IBM Plex Mono', monospace; font-weight: 600; letter-spacing: .05em; }

        .btn-refresh { background: #1A1D21; border: 1px solid #333; color: #D1D5DB; padding: 10px 16px; border-radius: 6px; cursor: pointer; font-family: 'IBM Plex Mono', monospace; font-size: 12px; transition: .2s; }
        .btn-refresh:hover { border-color: #29B5B5; color: #29B5B5; }

        .stats { display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin-bottom: 32px; }
        .stat { background: #121417; border: 1px solid #444444; border-radius: 6px; padding: 20px; border-left: 4px solid #444444; }
        .stat .val { font-size: 32px; font-weight: 400; font-family: 'IBM Plex Mono', monospace; color: #FFFFFF; }
        .stat .lbl { font-size: 10px; color: #9CA3AF; text-transform: uppercase; letter-spacing: .1em; margin-top: 8px; font-family: 'IBM Plex Mono', monospace; }

        .search-container { margin-bottom: 24px; }
        .search-box { width: 100%; max-width: 400px; padding: 12px 16px; background: #121417; border: 1px solid #444444; border-radius: 6px; color: #FFFFFF; font-family: 'IBM Plex Sans', sans-serif; font-size: 14px; outline: none; transition: border-color 0.2s; }
        .search-box:focus { border-color: #29B5B5; }

        .meta-name { color: #FFFFFF; font-weight: 600; }
        .meta-label { display: inline-block; padding: 4px 8px; border-radius: 999px; background: rgba(41,181,181,0.12); color: #7CE7E7; border: 1px solid rgba(41,181,181,0.25); font-size: 11px; }
        .meta-empty { color: #6B7280; font-size: 12px; }
        .btn-meta { background: transparent; border: 1px solid #3A4048; color: #D1D5DB; padding: 8px 10px; border-radius: 6px; cursor: pointer; font-family: 'IBM Plex Mono', monospace; font-size: 11px; text-transform: uppercase; }
        .btn-meta:hover { border-color: #29B5B5; color: #29B5B5; }

        .modal-backdrop { position: fixed; inset: 0; background: rgba(5, 6, 8, 0.78); display: none; align-items: center; justify-content: center; padding: 20px; z-index: 20; }
        .modal-backdrop.open { display: flex; }
        .modal-card { width: 100%; max-width: 460px; background: #121417; border: 1px solid #333; border-radius: 12px; padding: 24px; box-shadow: 0 20px 60px rgba(0, 0, 0, 0.45); }
        .modal-card h3 { margin: 0 0 8px; color: #FFFFFF; font-size: 18px; }
        .modal-card p { margin: 0 0 20px; color: #9CA3AF; font-size: 13px; }
        .modal-card label { display: block; margin-bottom: 8px; color: #D1D5DB; font-size: 12px; }
        .modal-card input { width: 100%; padding: 12px; margin-bottom: 16px; background: #08090A; border: 1px solid #333; color: #fff; border-radius: 6px; outline: none; font-family: 'IBM Plex Sans', sans-serif; }
        .modal-card input:focus { border-color: #29B5B5; }
        .modal-actions { display: flex; justify-content: flex-end; gap: 12px; }
        .btn-secondary { background: transparent; color: #D1D5DB; border: 1px solid #3A4048; padding: 10px 14px; border-radius: 6px; cursor: pointer; }
        .btn-primary { background: #29B5B5; color: #000; border: none; padding: 10px 14px; border-radius: 6px; cursor: pointer; font-weight: 700; }
        .modal-error { color: #EF4444; font-size: 12px; min-height: 18px; margin-bottom: 12px; white-space: pre-wrap; }

        /* Panel de rollout OTA */
        .rollout { background: #121417; border: 1px solid #444444; border-radius: 6px; padding: 20px; margin-bottom: 24px; }
        .rollout-head { display: flex; justify-content: space-between; align-items: center; gap: 16px; flex-wrap: wrap; margin-bottom: 16px; }
        .rollout-head h2 { margin: 0; font-size: 14px; color: #29B5B5; font-family: 'IBM Plex Mono', monospace; text-transform: uppercase; letter-spacing: .1em; }
        .rollout-actions { display: flex; gap: 10px; }
        .rollout-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 12px; }
        .rollout-item { background: #08090A; border: 1px solid #252A30; border-radius: 6px; padding: 12px 14px; }
        .rollout-item .k { font-size: 10px; color: #9CA3AF; text-transform: uppercase; letter-spacing: .1em; font-family: 'IBM Plex Mono', monospace; }
        .rollout-item .v { font-size: 18px; color: #FFFFFF; font-family: 'IBM Plex Mono', monospace; margin-top: 6px; }
        .bar { height: 6px; background: #252A30; border-radius: 999px; overflow: hidden; margin-top: 10px; }
        .bar > i { display: block; height: 100%; background: #10B981; }
        .ver-ok { color: #10B981; }
        .ver-old { color: #F59E0B; }
        .ver-bad { color: #EF4444; }
        .paused-tag { background: rgba(245,158,11,.15); color: #F59E0B; border: 1px solid rgba(245,158,11,.35); padding: 4px 8px; border-radius: 4px; font-size: 10px; font-family: 'IBM Plex Mono', monospace; text-transform: uppercase; }

        table { width: 100%; border-collapse: collapse; background: #121417; border-radius: 6px; overflow: hidden; border: 1px solid #444444; }
        th { background: #08090A; padding: 14px 16px; text-align: left; font-size: 10px; color: #9CA3AF; text-transform: uppercase; letter-spacing: .1em; font-family: 'IBM Plex Mono', monospace; border-bottom: 1px solid #444444; }
        td { padding: 14px 16px; border-bottom: 1px solid #252A30; font-size: 13px; }

        .row-critical { background: rgba(239, 68, 68, 0.05); border-left: 3px solid #EF4444; }
        .row-offline { opacity: 0.6; }
        .row-ok:hover { background: rgba(255,255,255,0.02); }

        .badge { padding: 4px 8px; border-radius: 4px; font-size: 10px; font-weight: 700; text-transform: uppercase; font-family: 'IBM Plex Mono', monospace; letter-spacing: .1em; }
        .bg-green { background: rgba(16, 185, 129, 0.15); color: #10B981; border: 1px solid rgba(16, 185, 129, 0.3); }
        .bg-red { background: rgba(239, 68, 68, 0.15); color: #EF4444; border: 1px solid rgba(239, 68, 68, 0.3); }

        @media (max-width: 900px) {
            .stats { grid-template-columns: repeat(2, 1fr); }
            #dashboard-view { padding: 20px; }
            .header { flex-direction: column; align-items: flex-start; gap: 16px; }
            table { display: block; overflow-x: auto; }
        }
    </style>
</head>
<body>

    <div id="login-view">
        <form class="login-box" onsubmit="handleLogin(event)">
            <h2>🔒 SafeLock SOC</h2>
            <p>Acceso restringido al equipo de telemetría</p>
            <input type="text" id="user" placeholder="Usuario" required autocomplete="username">
            <input type="password" id="pass" placeholder="Contraseña" required autocomplete="current-password">
            <button type="submit" id="loginBtn">Ingresar</button>
            <div id="loginError" class="error-msg">Credenciales incorrectas</div>
        </form>
    </div>

    <div id="dashboard-view">
        <div class="header">
            <div>
                <h1>🔒 OpenLock Telemetry SOC</h1>
                <div style="color: #9CA3AF; font-size: 13px; margin-top: 4px;">Gestión de Flota y Salud de Dispositivos</div>
            </div>
            <button class="btn-refresh" onclick="fetchData()" id="refreshBtn">Cargando...</button>
        </div>

        <div class="stats">
            <div class="stat" style="border-left-color: #0F5F5F"><div class="val" id="st-total">0</div><div class="lbl">Total unidades</div></div>
            <div class="stat" style="border-left-color: #10B981"><div class="val" id="st-online">0</div><div class="lbl">Online (OK)</div></div>
            <div class="stat" style="border-left-color: #EF4444"><div class="val" id="st-alerts">0</div><div class="lbl">Emergencias Activas</div></div>
            <div class="stat" style="border-left-color: #29B5B5"><div class="val" id="st-premium">0</div><div class="lbl">Premium Activos</div></div>
        </div>

        <div class="rollout">
            <div class="rollout-head">
                <h2>Rollout OTA</h2>
                <div class="rollout-actions">
                    <button class="btn-refresh" type="button" id="promoteBtn" onclick="promoteCanary()">Promover canary a toda la flota</button>
                    <button class="btn-refresh" type="button" id="pauseBtn" onclick="togglePause()">Pausar rollout</button>
                </div>
            </div>
            <div class="rollout-grid" id="rolloutGrid"></div>
            <div id="rolloutMsg" style="margin-top:12px;font-size:12px;color:#9CA3AF"></div>
        </div>

        <div class="search-container">
            <input type="text" id="searchBox" class="search-box" onkeyup="filterTable()" placeholder="Buscar por ID, nombre, etiqueta o IP de Tailscale...">
        </div>

        <table>
            <thead>
                <tr>
                    <th>Device ID</th>
                    <th>Nombre</th>
                    <th>Etiqueta</th>
                    <th>Versión</th>
                    <th>Estado y Salud</th>
                    <th>Plan Pi-hole</th>
                    <th>Tailscale IP</th>
                    <th>Último Reporte</th>
                    <th>Acciones</th>
                </tr>
            </thead>
            <tbody id="tableBody"></tbody>
        </table>
    </div>

    <div id="metadataModal" class="modal-backdrop">
        <div class="modal-card">
            <h3>Asignar nombre y etiqueta</h3>
            <p id="modalDeviceId"></p>

            <label for="deviceNameInput">Nombre del dispositivo</label>
            <input type="text" id="deviceNameInput" maxlength="80" placeholder="Ej. Recepción principal">

            <label for="deviceLabelInput">Etiqueta</label>
            <input type="text" id="deviceLabelInput" maxlength="60" placeholder="Ej. Puerta 1">

            <div id="metadataError" class="modal-error"></div>

            <div class="modal-actions">
                <button class="btn-secondary" type="button" onclick="closeMetadataModal()">Cancelar</button>
                <button class="btn-primary" type="button" id="saveMetadataBtn" onclick="saveMetadata()">Guardar</button>
            </div>
        </div>
    </div>

    <script>
        let fleetDevices = [];
        let activeDeviceId = null;
        let fleetTargets = {};

        function handleLogin(e) {
            e.preventDefault();

            const u = document.getElementById('user').value.trim();
            const p = document.getElementById('pass').value.trim();
            const token = btoa(u + ':' + p);

            document.getElementById('loginBtn').innerText = "Validando...";

            fetch('/api/auth-check', { headers: { 'Authorization': 'Basic ' + token } })
                .then(res => {
                    if (res.ok) {
                        localStorage.setItem('soc_auth', token);
                        showDashboard();
                        fetchData();
                        return null;
                    }

                    if (res.status === 401) throw new Error('Unauthorized');
                    throw new Error('ServerError');
                })
                .catch(err => {
                    document.getElementById('loginBtn').innerText = "Ingresar";
                    const errorEl = document.getElementById('loginError');
                    errorEl.style.display = 'block';
                    errorEl.innerText = err.message === 'Unauthorized'
                        ? 'Credenciales incorrectas'
                        : 'No se pudo validar el acceso. Revisa el servidor.';
                });
        }

        function showDashboard() {
            document.getElementById('login-view').style.display = 'none';
            document.getElementById('dashboard-view').style.display = 'block';
        }

        function fetchData() {
            const token = localStorage.getItem('soc_auth');
            if (!token) return;

            const btn = document.getElementById('refreshBtn');
            btn.innerText = "Sincronizando...";

            fetch('/api/fleet', { headers: { 'Authorization': 'Basic ' + token } })
                .then(async res => {
                    if (res.status === 401) {
                        localStorage.removeItem('soc_auth');
                        window.location.reload();
                        return;
                    }

                    const data = await res.json();

                    if (!res.ok) {
                        console.error("Error cargando fleet:", data);
                        throw new Error(data.detail || 'No se pudo cargar la flota');
                    }

                    return data;
                })
                .then(data => {
                    if (!data) return;
                    processData(data);
                    const now = new Date().toLocaleTimeString('es-ES', { hour12: false });
                    btn.innerText = "Actualizar (Última vez: " + now + ")";
                    filterTable();
                })
                .catch(err => {
                    console.error(err);
                    btn.innerText = "Actualizar";
                    alert("Error al cargar flota: " + err.message);
                });
        }

        function processData(data) {
            let devices = data.devices || [];
            fleetDevices = devices;
            fleetTargets = data.targets || {};
            renderRollout(devices);

            devices.sort((a, b) => {
                if (a.critical_alert && !b.critical_alert) return -1;
                if (b.critical_alert && !a.critical_alert) return 1;

                if (a.status === 'offline' && b.status === 'online') return -1;
                if (b.status === 'offline' && a.status === 'online') return 1;

                return new Date(b.last_seen) - new Date(a.last_seen);
            });

            let tOnline = 0, tAlerts = 0, tPrem = 0;

            devices.forEach(d => {
                if (d.status === 'online') tOnline++;
                if (d.critical_alert) tAlerts++;
                if (d.pihole_active && d.status === 'online') tPrem++;
            });

            document.getElementById('st-total').innerText = devices.length;
            document.getElementById('st-online').innerText = tOnline;
            document.getElementById('st-alerts').innerText = tAlerts;
            document.getElementById('st-premium').innerText = tPrem;

            filterTable();
        }

        function renderTable(devices) {
            let html = "";

            devices.forEach(d => {
                let rowClass = "row-ok";
                let statusBadge = `<span class="badge bg-green">SISTEMA OK</span>`;

                if (d.status === 'offline') {
                    rowClass = "row-offline";
                    statusBadge = `<span class="badge" style="background:#374151;color:#D1D5DB">OFFLINE</span>`;
                } else if (d.critical_alert) {
                    rowClass = "row-critical";
                    statusBadge = `<span class="badge bg-red">🚨 ALERTA ROJA</span>`;
                }

                let piholeBadge = d.pihole_active
                    ? `<span class="badge bg-green">PREMIUM</span>`
                    : `<span class="badge bg-red">SUSPENDIDO</span>`;

                let verClass = d.up_to_date ? 'ver-ok' : 'ver-old';
                let verNota = '';
                const otaState = d.ota_state || '';
                if (otaState === 'failed' || (d.ota && d.ota.last_result === 'rollback')) {
                    verClass = 'ver-bad';
                    verNota = '<div style="font-size:10px;color:#EF4444">rollback</div>';
                } else if (otaState === 'rescue') {
                    verClass = 'ver-bad';
                    verNota = '<div style="font-size:10px;color:#EF4444">rescate</div>';
                } else if (otaState === 'updating') {
                    verNota = '<div style="font-size:10px;color:#9CA3AF">actualizando…</div>';
                } else if (!d.migrated) {
                    verNota = '<div style="font-size:10px;color:#F59E0B">sin migrar</div>';
                }

                html += `
                <tr class="${rowClass}">
                    <td style="font-family:'IBM Plex Mono',monospace;font-size:13px;color:#FFFFFF;font-weight:600;">${escapeHtml(d.device_id)}</td>
                    <td>${d.display_name ? `<span class="meta-name">${escapeHtml(d.display_name)}</span>` : '<span class="meta-empty">Sin nombre</span>'}</td>
                    <td>${d.label ? `<span class="meta-label">${escapeHtml(d.label)}</span>` : '<span class="meta-empty">Sin etiqueta</span>'}</td>
                    <td style="font-family:'IBM Plex Mono',monospace;font-size:12px"><span class="${verClass}">${escapeHtml(d.version || '—')}</span>${verNota}</td>
                    <td>${statusBadge}</td>
                    <td>${piholeBadge}</td>
                    <td style="font-family:'IBM Plex Mono',monospace;font-size:12px;color:#9CA3AF">${escapeHtml(d.tailscale_ip || 'Sin configurar')}</td>
                    <td style="color:#9CA3AF;font-size:12px">${escapeHtml(d.time_ago)}</td>
                    <td><button class="btn-meta" type="button" data-device-id="${escapeHtml(d.device_id)}" onclick="openMetadataModal(this.dataset.deviceId)">Editar</button></td>
                </tr>`;
            });

            document.getElementById('tableBody').innerHTML =
                html || '<tr><td colspan="9" style="text-align:center;color:#9CA3AF;padding:40px">Sin dispositivos en flota</td></tr>';
        }

        function renderRollout(devices) {
            const stable = fleetTargets.stable || {};
            const canary = fleetTargets.canary || {};
            const objetivo = stable.tag || null;

            const alDia = devices.filter(d => objetivo && d.version === objetivo).length;
            const migrados = devices.filter(d => d.migrated).length;
            const problemas = devices.filter(d =>
                d.ota_state === 'failed' || d.ota_state === 'rescue' ||
                (d.ota && d.ota.last_result === 'rollback')).length;
            const pct = devices.length ? Math.round(alDia * 100 / devices.length) : 0;

            const versiones = {};
            devices.forEach(d => {
                const v = d.version || 'desconocida';
                versiones[v] = (versiones[v] || 0) + 1;
            });
            const desglose = Object.keys(versiones).sort()
                .map(v => `${escapeHtml(v)}: ${versiones[v]}`).join(' · ') || '—';

            document.getElementById('rolloutGrid').innerHTML = `
                <div class="rollout-item">
                    <div class="k">Versión objetivo (stable)</div>
                    <div class="v">${escapeHtml(objetivo || 'sin definir')}</div>
                    ${stable.paused ? '<div style="margin-top:8px"><span class="paused-tag">rollout en pausa</span></div>' : ''}
                </div>
                <div class="rollout-item">
                    <div class="k">En canary</div>
                    <div class="v">${escapeHtml(canary.tag || '—')}</div>
                </div>
                <div class="rollout-item">
                    <div class="k">Flota al día</div>
                    <div class="v">${alDia} / ${devices.length}</div>
                    <div class="bar"><i style="width:${pct}%"></i></div>
                </div>
                <div class="rollout-item">
                    <div class="k">Migrados a OTA v2</div>
                    <div class="v">${migrados} / ${devices.length}</div>
                </div>
                <div class="rollout-item">
                    <div class="k">Con problemas</div>
                    <div class="v" style="color:${problemas ? '#EF4444' : '#FFFFFF'}">${problemas}</div>
                </div>`;

            document.getElementById('pauseBtn').innerText =
                stable.paused ? 'Reanudar rollout' : 'Pausar rollout';
            document.getElementById('rolloutMsg').innerText = 'Versiones en flota — ' + desglose;
        }

        function otaPost(ruta, cuerpo, exito) {
            const token = localStorage.getItem('soc_auth');
            if (!token) return;

            const msg = document.getElementById('rolloutMsg');
            msg.innerText = 'Aplicando…';

            fetch(ruta, {
                method: 'POST',
                headers: { 'Authorization': 'Basic ' + token, 'Content-Type': 'application/json' },
                body: JSON.stringify(cuerpo)
            })
                .then(async res => {
                    const data = await res.json();
                    if (!res.ok) throw new Error(data.detail || 'Falló la operación');
                    msg.innerText = exito;
                    fetchData();
                })
                .catch(err => { msg.innerText = 'Error: ' + err.message; });
        }

        function promoteCanary() {
            const canary = fleetTargets.canary || {};
            if (!canary.tag) {
                document.getElementById('rolloutMsg').innerText = 'No hay ningún release en canary.';
                return;
            }
            if (!confirm('Promover ' + canary.tag + ' a toda la flota?')) return;
            otaPost('/api/ota/promote', { tag: canary.tag, channel: 'stable' },
                    canary.tag + ' promovido a stable.');
        }

        function togglePause() {
            const stable = fleetTargets.stable || {};
            const pausar = !stable.paused;
            otaPost('/api/ota/pause', { paused: pausar, channel: 'stable' },
                    pausar ? 'Rollout pausado.' : 'Rollout reanudado.');
        }

        function filterTable() {
            const input = document.getElementById("searchBox");
            if (!input) return;

            const filter = input.value.trim().toUpperCase();

            const filtered = fleetDevices.filter(device => {
                const haystack = [
                    device.device_id || "",
                    device.tailscale_ip || "",
                    device.display_name || "",
                    device.label || ""
                ].join(" ").toUpperCase();

                return haystack.indexOf(filter) > -1;
            });

            renderTable(filtered);
        }

        function openMetadataModal(deviceId) {
            const device = fleetDevices.find(d => d.device_id === deviceId);
            activeDeviceId = deviceId;
            document.getElementById('modalDeviceId').innerText = deviceId;
            document.getElementById('deviceNameInput').value = device && device.display_name ? device.display_name : '';
            document.getElementById('deviceLabelInput').value = device && device.label ? device.label : '';
            document.getElementById('metadataError').innerText = '';
            document.getElementById('metadataModal').classList.add('open');
        }

        function closeMetadataModal() {
            activeDeviceId = null;
            document.getElementById('metadataModal').classList.remove('open');
        }

        async function saveMetadata() {
            const token = localStorage.getItem('soc_auth');
            if (!token || !activeDeviceId) return;

            const displayName = document.getElementById('deviceNameInput').value.trim();
            const label = document.getElementById('deviceLabelInput').value.trim();
            const saveBtn = document.getElementById('saveMetadataBtn');
            const errorBox = document.getElementById('metadataError');

            saveBtn.innerText = 'Guardando...';
            saveBtn.disabled = true;
            errorBox.innerText = '';

            try {
                const res = await fetch('/api/device-metadata/' + encodeURIComponent(activeDeviceId), {
                    method: 'POST',
                    headers: {
                        'Authorization': 'Basic ' + token,
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({ display_name: displayName, label: label })
                });

                let responseData = null;
                let rawText = '';

                try {
                    rawText = await res.text();
                    responseData = rawText ? JSON.parse(rawText) : null;
                } catch (parseErr) {
                    responseData = null;
                }

                if (!res.ok) {
                    console.error('Error guardando metadata:', {
                        status: res.status,
                        body: rawText
                    });

                    const message = responseData?.detail || rawText || 'No se pudo guardar la información del dispositivo.';
                    throw new Error(message);
                }

                const device = fleetDevices.find(d => d.device_id === activeDeviceId);
                if (device) {
                    device.display_name = displayName;
                    device.label = label;
                }

                closeMetadataModal();
                filterTable();

            } catch (err) {
                errorBox.innerText = err.message || 'No se pudo guardar la información del dispositivo.';
            } finally {
                saveBtn.innerText = 'Guardar';
                saveBtn.disabled = false;
            }
        }

        function escapeHtml(value) {
            return String(value)
                .replace(/&/g, '&amp;')
                .replace(/</g, '&lt;')
                .replace(/>/g, '&gt;')
                .replace(/"/g, '&quot;')
                .replace(/'/g, '&#39;');
        }

        if (localStorage.getItem('soc_auth')) {
            const token = localStorage.getItem('soc_auth');
            fetch('/api/auth-check', { headers: { 'Authorization': 'Basic ' + token } })
                .then(res => {
                    if (res.ok) {
                        showDashboard();
                        fetchData();
                    } else {
                        localStorage.removeItem('soc_auth');
                    }
                })
                .catch(() => localStorage.removeItem('soc_auth'));
        }
    </script>
</body>
</html>"""
    return html_content


@app.get("/")
def root():
    return RedirectResponse(url="/dashboard")


@app.get("/status")
def status():
    return {"service": "SafeLock Telemetry", "status": "active", "version": "2.0.0"}
