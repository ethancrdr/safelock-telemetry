from fastapi import FastAPI, Header, HTTPException, Depends
from fastapi.responses import HTMLResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from pydantic import BaseModel
from datetime import datetime, timedelta, timezone
import os
import httpx
import secrets

app = FastAPI(title="SafeLock Telemetry SOC")

API_SECRET = os.environ.get("API_SECRET", "openlock2026")
SUPABASE_URL = os.environ.get("SUPABASE_URL")
SUPABASE_KEY = os.environ.get("SUPABASE_KEY")

security = HTTPBasic()

def sb_headers():
    return {
        "apikey": SUPABASE_KEY,
        "Authorization": f"Bearer {SUPABASE_KEY}",
        "Content-Type": "application/json",
        "Prefer": "resolution=merge-duplicates"
    }

# --- Seguridad para el Dashboard Web ---
def verificar_acceso_dashboard(credentials: HTTPBasicCredentials = Depends(security)):
    usuario_correcto = secrets.compare_digest(credentials.username, "admin")
    clave_correcta = secrets.compare_digest(credentials.password, API_SECRET)
    if not (usuario_correcto and clave_correcta):
        raise HTTPException(
            status_code=401,
            detail="Acceso denegado a la Telemetría de OpenLock",
            headers={"WWW-Authenticate": "Basic"},
        )
    return credentials.username

class Heartbeat(BaseModel):
    device_id: str
    pihole_active: bool
    tailscale_ip: str = ""
    version: str = "1.0"

@app.post("/heartbeat")
async def heartbeat(data: Heartbeat, x_api_secret: str = Header(None)):
    if x_api_secret != API_SECRET:
        raise HTTPException(status_code=401, detail="Unauthorized")
    
    payload = {
        "device_id": data.device_id,
        "pihole_active": data.pihole_active,
        "tailscale_ip": data.tailscale_ip,
        "version": data.version,
        "last_seen": datetime.now(timezone.utc).isoformat(),
        "status": "online"
    }
    
    async with httpx.AsyncClient() as client:
        r = await client.post(
            f"{SUPABASE_URL}/rest/v1/devices?on_conflict=device_id",
            headers=sb_headers(),
            json=payload
        )
    return {"ok": r.status_code in [200, 201, 204]}

@app.get("/devices")
async def get_devices(x_api_secret: str = Header(None)):
    if x_api_secret != API_SECRET:
        raise HTTPException(status_code=401, detail="Unauthorized")
        
    async with httpx.AsyncClient() as client:
        r = await client.get(
            f"{SUPABASE_URL}/rest/v1/devices?select=device_id,pihole_active,tailscale_ip,last_seen,version&order=last_seen.desc&limit=500",
            headers=sb_headers()
        )
        
    if r.status_code != 200:
        raise HTTPException(status_code=500, detail=f"Error de Supabase: {r.text}")

    rows = r.json()
    now = datetime.now(timezone.utc)
    online = pihole_active = 0
    valid_rows = []
    
    for d in rows:
        last_seen_str = d.get("last_seen")
        if not last_seen_str:
            continue
            
        try:
            last = datetime.fromisoformat(last_seen_str.replace("Z", "+00:00"))
            # Corrección del error offset-naive vs offset-aware
            if last.tzinfo is None:
                last = last.replace(tzinfo=timezone.utc)
                
            is_online = (now - last) < timedelta(minutes=15)
            d["status"] = "online" if is_online else "offline"
            if is_online: online += 1
            if is_online and d.get("pihole_active"): pihole_active += 1
            valid_rows.append(d)
        except ValueError:
            continue
        
    return {"total": len(valid_rows), "online": online, "offline": len(valid_rows) - online, "pihole_active": pihole_active, "devices": valid_rows}

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(username: str = Depends(verificar_acceso_dashboard)):
    async with httpx.AsyncClient() as client:
        r = await client.get(
            f"{SUPABASE_URL}/rest/v1/devices?select=device_id,pihole_active,tailscale_ip,last_seen,version&order=last_seen.desc&limit=500",
            headers=sb_headers()
        )
        
    if r.status_code != 200:
        return HTMLResponse(f"<h1>Error conectando a Supabase</h1><p>Status: {r.status_code}</p><p>Detalle: {r.text}</p>", status_code=500)

    rows = r.json()
    
    if isinstance(rows, dict):
        return HTMLResponse(f"<h1>Error de Formato</h1><p>Supabase devolvió: {rows}</p>", status_code=500)

    now = datetime.now(timezone.utc)
    rows_html = ""
    online = offline = pihole_on = 0
    
    for d in rows:
        last_seen_str = d.get("last_seen")
        if not last_seen_str:
            continue
            
        try:
            last = datetime.fromisoformat(last_seen_str.replace("Z", "+00:00"))
            # Corrección del error offset-naive vs offset-aware
            if last.tzinfo is None:
                last = last.replace(tzinfo=timezone.utc)
        except ValueError:
            continue
            
        is_online = (now - last) < timedelta(minutes=15)
        
        status_class = "bg-green" if is_online else "bg-red"
        status_label = "ONLINE" if is_online else "OFFLINE"
        pihole_class = "bg-green" if d.get("pihole_active") else "bg-red"
        pihole_label = "PREMIUM" if d.get("pihole_active") else "SUSPENDIDO"
        
        tailscale = d.get('tailscale_ip')
        tailscale_disp = tailscale if tailscale else "Sin configurar"
        
        if is_online: online += 1
        else: offline += 1
        if is_online and d.get("pihole_active"): pihole_on += 1
        
        ago = now - last
        mins = int(ago.total_seconds() / 60)
        time_str = f"hace {mins}m" if mins < 60 else f"hace {mins//60}h"
        
        rows_html += f"""
        <tr>
            <td style="font-family:'IBM Plex Mono',monospace;font-size:13px;color:#FFFFFF">{d.get('device_id', 'Desconocido')}</td>
            <td><span class="badge {status_class}">{status_label}</span></td>
            <td><span class="badge {pihole_class}">{pihole_label}</span></td>
            <td style="font-family:'IBM Plex Mono',monospace;font-size:12px;color:#9CA3AF">{tailscale_disp}</td>
            <td style="color:#9CA3AF;font-size:12px">{time_str}</td>
        </tr>"""
        
    total = online + offline
    
    html = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>OpenLock Telemetry</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
  @import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@400;500;600&family=IBM+Plex+Mono:wght@400;600;700&display=swap');
  body {{ background: #050608; color: #D1D5DB; font-family: 'IBM Plex Sans', sans-serif; padding: 32px; margin: 0; }}
  h1 {{ color: #29B5B5; font-size: 24px; margin-bottom: 4px; font-family: 'IBM Plex Mono', monospace; font-weight: 600; letter-spacing: .05em; }}
  .sub {{ color: #9CA3AF; font-size: 13px; margin-bottom: 24px; }}
  
  .search-container {{ margin-bottom: 24px; }}
  .search-box {{ width: 100%; max-width: 400px; padding: 12px 16px; background: #121417; border: 1px solid #444444; border-radius: 6px; color: #FFFFFF; font-family: 'IBM Plex Sans', sans-serif; font-size: 14px; outline: none; transition: border-color 0.2s; }}
  .search-box:focus {{ border-color: #29B5B5; }}

  .stats {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin-bottom: 32px; }}
  .stat {{ background: #121417; border: 1px solid #444444; border-radius: 6px; padding: 20px; border-left: 4px solid #444444; }}
  .stat.brand {{ border-left-color: #0F5F5F; }}
  .stat.ok {{ border-left-color: #10B981; }}
  .stat.err {{ border-left-color: #EF4444; }}
  .stat.prem {{ border-left-color: #29B5B5; }}
  .stat .val {{ font-size: 32px; font-weight: 400; font-family: 'IBM Plex Mono', monospace; color: #FFFFFF; }}
  .stat .lbl {{ font-size: 10px; color: #9CA3AF; text-transform: uppercase; letter-spacing: .1em; margin-top: 8px; font-family: 'IBM Plex Mono', monospace; }}
  
  table {{ width: 100%; border-collapse: collapse; background: #121417; border-radius: 6px; overflow: hidden; border: 1px solid #444444; }}
  th {{ background: #08090A; padding: 14px 16px; text-align: left; font-size: 10px; color: #9CA3AF; text-transform: uppercase; letter-spacing: .1em; font-family: 'IBM Plex Mono', monospace; border-bottom: 1px solid #444444; }}
  td {{ padding: 14px 16px; border-bottom: 1px solid #252A30; font-size: 13px; }}
  tr:hover {{ background: rgba(255,255,255,0.02); }}
  
  .badge {{ padding: 4px 8px; border-radius: 4px; font-size: 10px; font-weight: 700; text-transform: uppercase; font-family: 'IBM Plex Mono', monospace; letter-spacing: .1em; }}
  .bg-green {{ background: rgba(16, 185, 129, 0.15); color: #10B981; border: 1px solid rgba(16, 185, 129, 0.3); }}
  .bg-red {{ background: rgba(239, 68, 68, 0.15); color: #EF4444; border: 1px solid rgba(239, 68, 68, 0.3); }}
</style>
<script>
  function filterTable() {{
    let input = document.getElementById("searchBox");
    let filter = input.value.toUpperCase();
    let table = document.getElementById("deviceTable");
    let tr = table.getElementsByTagName("tr");
    
    for (let i = 1; i < tr.length; i++) {{
      let tdID = tr[i].getElementsByTagName("td")[0];
      let tdIP = tr[i].getElementsByTagName("td")[3];
      if (tdID || tdIP) {{
        let txtValueID = tdID.textContent || tdID.innerText;
        let txtValueIP = tdIP.textContent || tdIP.innerText;
        if (txtValueID.toUpperCase().indexOf(filter) > -1 || txtValueIP.toUpperCase().indexOf(filter) > -1) {{
          tr[i].style.display = "";
        }} else {{
          tr[i].style.display = "none";
        }}
      }}
    }}
  }}
  setTimeout(() => {{ if(!document.getElementById('searchBox').value) window.location.reload(); }}, 60000);
</script>
</head><body>
<h1>🔒 OpenLock Telemetry SOC</h1>
<div class="sub">Panel de Control Interno · Actualización en tiempo real</div>

<div class="stats">
  <div class="stat brand"><div class="val">{total}</div><div class="lbl">Total unidades</div></div>
  <div class="stat ok"><div class="val">{online}</div><div class="lbl">SafeLocks Online</div></div>
  <div class="stat err"><div class="val">{offline}</div><div class="lbl">SafeLocks Offline</div></div>
  <div class="stat prem"><div class="val">{pihole_on}</div><div class="lbl">Suscripciones Premium</div></div>
</div>

<div class="search-container">
  <input type="text" id="searchBox" class="search-box" onkeyup="filterTable()" placeholder="Buscar por ID de dispositivo o IP de Tailscale...">
</div>

<table id="deviceTable">
  <tr><th>Device ID</th><th>Estado Red</th><th>Plan Pi-hole</th><th>Tailscale IP (Acceso)</th><th>Último Reporte</th></tr>
  {rows_html if rows_html else '<tr><td colspan="5" style="text-align:center;color:#9CA3AF;padding:40px">Sin dispositivos reportando a la flota</td></tr>'}
</table>
</body></html>"""
    return HTMLResponse(html)

@app.get("/")
def root():
    return {"service": "SafeLock Telemetry", "status": "active", "version": "1.1.0"}
