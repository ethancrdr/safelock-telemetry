from fastapi import FastAPI, Header, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from datetime import datetime, timedelta
import os
import httpx

app = FastAPI(title="SafeLock Telemetry")

API_SECRET = os.environ.get("API_SECRET", "openlock2026")
SUPABASE_URL = os.environ.get("SUPABASE_URL")
SUPABASE_KEY = os.environ.get("SUPABASE_KEY")

def sb_headers():
    return {
        "apikey": SUPABASE_KEY,
        "Authorization": f"Bearer {SUPABASE_KEY}",
        "Content-Type": "application/json",
        "Prefer": "resolution=merge-duplicates"
    }

class Heartbeat(BaseModel):
    device_id: str
    pihole_active: bool
    tailscale_ip: str = ""
    version: str = "1.0"

@app.post("/heartbeat")
def heartbeat(data: Heartbeat, x_api_secret: str = Header(None)):
    if x_api_secret != API_SECRET:
        raise HTTPException(status_code=401, detail="Unauthorized")
    payload = {
        "device_id": data.device_id,
        "pihole_active": data.pihole_active,
        "tailscale_ip": data.tailscale_ip,
        "version": data.version,
        "last_seen": datetime.utcnow().isoformat(),
        "status": "online"
    }
    r = httpx.post(
        f"{SUPABASE_URL}/rest/v1/devices",
        headers=sb_headers(),
        json=payload
    )
    return {"ok": r.status_code in [200, 201]}

@app.get("/devices")
def get_devices(x_api_secret: str = Header(None)):
    if x_api_secret != API_SECRET:
        raise HTTPException(status_code=401, detail="Unauthorized")
    r = httpx.get(
        f"{SUPABASE_URL}/rest/v1/devices?select=*&order=last_seen.desc",
        headers=sb_headers()
    )
    rows = r.json()
    now = datetime.utcnow()
    online = pihole_active = 0
    for d in rows:
        last = datetime.fromisoformat(d["last_seen"])
        is_online = (now - last) < timedelta(minutes=15)
        d["status"] = "online" if is_online else "offline"
        if is_online: online += 1
        if is_online and d["pihole_active"]: pihole_active += 1
    return {"total": len(rows), "online": online, "offline": len(rows) - online, "pihole_active": pihole_active, "devices": rows}

@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(x_api_secret: str = None):
    if x_api_secret != API_SECRET:
        return HTMLResponse("<h1>401 Unauthorized</h1>", status_code=401)
    r = httpx.get(
        f"{SUPABASE_URL}/rest/v1/devices?select=*&order=last_seen.desc",
        headers=sb_headers()
    )
    rows = r.json()
    now = datetime.utcnow()
    rows_html = ""
    online = offline = pihole_on = 0
    for d in rows:
        last = datetime.fromisoformat(d["last_seen"])
        is_online = (now - last) < timedelta(minutes=15)
        status_color = "#22c55e" if is_online else "#ef4444"
        status_label = "Online" if is_online else "Offline"
        pihole_color = "#22c55e" if d["pihole_active"] else "#ef4444"
        pihole_label = "Activo" if d["pihole_active"] else "Inactivo"
        if is_online: online += 1
        else: offline += 1
        if is_online and d["pihole_active"]: pihole_on += 1
        ago = now - last
        mins = int(ago.total_seconds() / 60)
        time_str = f"hace {mins}m" if mins < 60 else f"hace {mins//60}h"
        rows_html += f"""
        <tr>
            <td style="font-family:monospace;font-size:13px">{d['device_id']}</td>
            <td><span style="color:{status_color};font-weight:bold">{status_label}</span></td>
            <td><span style="color:{pihole_color};font-weight:bold">{pihole_label}</span></td>
            <td style="font-family:monospace;font-size:12px;color:#64748b">{d.get('tailscale_ip','—')}</td>
            <td style="color:#64748b;font-size:12px">{time_str}</td>
        </tr>"""
    total = len(rows)
    html = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>SafeLock Telemetry</title>
<meta http-equiv="refresh" content="60">
<style>
  body{{background:#070c14;color:#e2e8f0;font-family:Arial,sans-serif;padding:32px;}}
  h1{{color:#00d4ff;font-size:24px;margin-bottom:4px}}
  .sub{{color:#475569;font-size:13px;margin-bottom:32px}}
  .stats{{display:grid;grid-template-columns:repeat(4,1fr);gap:16px;margin-bottom:32px}}
  .stat{{background:rgba(255,255,255,0.04);border:1px solid rgba(255,255,255,0.08);border-radius:12px;padding:20px}}
  .stat .val{{font-size:36px;font-weight:700;font-family:monospace}}
  .stat .lbl{{font-size:11px;color:#475569;text-transform:uppercase;letter-spacing:.1em;margin-top:4px}}
  table{{width:100%;border-collapse:collapse;background:rgba(255,255,255,0.02);border-radius:12px;overflow:hidden}}
  th{{background:rgba(0,0,0,0.3);padding:12px 16px;text-align:left;font-size:11px;color:#475569;text-transform:uppercase;letter-spacing:.1em}}
  td{{padding:12px 16px;border-bottom:1px solid rgba(255,255,255,0.04)}}
</style></head><body>
<h1>🔒 SafeLock Telemetry</h1>
<div class="sub">OpenLock Security — Panel interno · Se actualiza cada 60 segundos</div>
<div class="stats">
  <div class="stat"><div class="val" style="color:#00d4ff">{total}</div><div class="lbl">Total unidades</div></div>
  <div class="stat"><div class="val" style="color:#22c55e">{online}</div><div class="lbl">Online</div></div>
  <div class="stat"><div class="val" style="color:#ef4444">{offline}</div><div class="lbl">Offline</div></div>
  <div class="stat"><div class="val" style="color:#a855f7">{pihole_on}</div><div class="lbl">Pi-hole activo</div></div>
</div>
<table>
  <tr><th>Device ID</th><th>Estado</th><th>Pi-hole</th><th>Tailscale IP</th><th>Último reporte</th></tr>
  {rows_html if rows_html else '<tr><td colspan="5" style="text-align:center;color:#475569;padding:32px">Sin dispositivos registrados</td></tr>'}
</table>
</body></html>"""
    return HTMLResponse(html)

@app.get("/")
def root():
    return {"service": "SafeLock Telemetry", "version": "1.0.0"}
