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

# --- Seguridad ---
def verificar_acceso_dashboard(credentials: HTTPBasicCredentials = Depends(security)):
    usuario_correcto = secrets.compare_digest(credentials.username, "admin")
    clave_correcta = secrets.compare_digest(credentials.password, API_SECRET)
    if not (usuario_correcto and clave_correcta):
        raise HTTPException(
            status_code=401,
            detail="Acceso denegado a la Telemetría",
            headers={"WWW-Authenticate": "Basic"},
        )
    return credentials.username

# --- MODELO ACTUALIZADO: Bandera de Alerta Crítica ---
class Heartbeat(BaseModel):
    device_id: str
    pihole_active: bool
    tailscale_ip: str = ""
    version: str = "1.0"
    critical_alert: bool = False  # <-- Solo será True si hay un fallo/ataque serio

@app.post("/heartbeat")
async def heartbeat(data: Heartbeat, x_api_secret: str = Header(None)):
    if x_api_secret != API_SECRET:
        raise HTTPException(status_code=401, detail="Unauthorized")
    
    payload = {
        "device_id": data.device_id,
        "pihole_active": data.pihole_active,
        "tailscale_ip": data.tailscale_ip,
        "version": data.version,
        "critical_alert": data.critical_alert, # Guardamos el estado de emergencia
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

@app.get("/api/fleet")
async def get_fleet_data(username: str = Depends(verificar_acceso_dashboard)):
    async with httpx.AsyncClient() as client:
        r = await client.get(
            f"{SUPABASE_URL}/rest/v1/devices?select=device_id,pihole_active,tailscale_ip,last_seen,version,critical_alert&limit=500",
            headers=sb_headers()
        )
        
    if r.status_code != 200:
        raise HTTPException(status_code=500, detail=f"Error de Supabase: {r.text}")

    rows = r.json()
    now = datetime.now(timezone.utc)
    valid_rows = []
    
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
            d["time_ago"] = f"hace {mins}m" if mins < 60 else f"hace {mins//60}h"
            d["critical_alert"] = d.get("critical_alert", False) 
            
            valid_rows.append(d)
        except ValueError:
            continue
            
    return {"devices": valid_rows}

# --- EL FRONTEND HTML/JS ---
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

        table { width: 100%; border-collapse: collapse; background: #121417; border-radius: 6px; overflow: hidden; border: 1px solid #444444; }
        th { background: #08090A; padding: 14px 16px; text-align: left; font-size: 10px; color: #9CA3AF; text-transform: uppercase; letter-spacing: .1em; font-family: 'IBM Plex Mono', monospace; border-bottom: 1px solid #444444; }
        td { padding: 14px 16px; border-bottom: 1px solid #252A30; font-size: 13px; }
        
        /* Animación para el parpadeo de alerta roja */
        @keyframes pulse-red {
            0% { background-color: rgba(239, 68, 68, 0.05); }
            50% { background-color: rgba(239, 68, 68, 0.2); }
            100% { background-color: rgba(239, 68, 68, 0.05); }
        }

        .row-critical { animation: pulse-red 2s infinite; border-left: 3px solid #EF4444; }
        .row-offline { opacity: 0.6; }
        .row-ok:hover { background: rgba(255,255,255,0.02); }

        .badge { padding: 4px 8px; border-radius: 4px; font-size: 10px; font-weight: 700; text-transform: uppercase; font-family: 'IBM Plex Mono', monospace; letter-spacing: .1em; }
        .bg-green { background: rgba(16, 185, 129, 0.15); color: #10B981; border: 1px solid rgba(16, 185, 129, 0.3); }
        .bg-red { background: rgba(239, 68, 68, 0.15); color: #EF4444; border: 1px solid rgba(239, 68, 68, 0.3); }
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

        <table>
            <thead>
                <tr>
                    <th>Device ID</th>
                    <th>Estado y Salud</th>
                    <th>Plan Pi-hole</th>
                    <th>Tailscale IP</th>
                    <th>Último Reporte</th>
                </tr>
            </thead>
            <tbody id="tableBody">
            </tbody>
        </table>
    </div>

    <script>
        function handleLogin(e) {
            e.preventDefault();
            const u = document.getElementById('user').value;
            const p = document.getElementById('pass').value;
            const token = btoa(u + ':' + p);
            
            document.getElementById('loginBtn').innerText = "Validando...";
            
            fetch('/api/fleet', { headers: { 'Authorization': 'Basic ' + token } })
                .then(res => {
                    if (res.ok) {
                        localStorage.setItem('soc_auth', token);
                        showDashboard();
                        processData(res);
                    } else throw new Error('Unauthorized');
                })
                .catch(err => {
                    document.getElementById('loginBtn').innerText = "Ingresar";
                    document.getElementById('loginError').style.display = 'block';
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
                .then(res => {
                    if (res.status === 401) {
                        localStorage.removeItem('soc_auth');
                        window.location.reload();
                    }
                    return res.json();
                })
                .then(data => {
                    processData(data);
                    const now = new Date().toLocaleTimeString('es-ES', { hour12: false });
                    btn.innerText = "Actualizar (Última vez: " + now + ")";
                })
                .catch(err => console.error(err));
        }

        function processData(data) {
            let devices = data.devices || [];
            
            // ORDENAMIENTO DE SALUD: 1° Alerta Roja, 2° Offline, 3° Online OK
            devices.sort((a, b) => {
                if (a.critical_alert && !b.critical_alert) return -1;
                if (b.critical_alert && !a.critical_alert) return 1;
                
                if (a.status === 'offline' && b.status === 'online') return -1;
                if (b.status === 'offline' && a.status === 'online') return 1;
                
                return new Date(b.last_seen) - new Date(a.last_seen);
            });

            let tOnline = 0, tAlerts = 0, tPrem = 0;
            let html = "";

            devices.forEach(d => {
                if (d.status === 'online') tOnline++;
                if (d.critical_alert) tAlerts++;
                if (d.pihole_active && d.status === 'online') tPrem++;

                let rowClass = "row-ok";
                let statusBadge = `<span class="badge bg-green">SISTEMA OK</span>`;
                
                if (d.status === 'offline') {
                    rowClass = "row-offline";
                    statusBadge = `<span class="badge" style="background:#374151;color:#D1D5DB">OFFLINE</span>`;
                } else if (d.critical_alert) {
                    rowClass = "row-critical"; // Animación de parpadeo rojo
                    statusBadge = `<span class="badge bg-red">🚨 ALERTA ROJA</span>`;
                }

                let piholeBadge = d.pihole_active 
                    ? `<span class="badge bg-green">PREMIUM</span>` 
                    : `<span class="badge bg-red">SUSPENDIDO</span>`;

                html += `
                <tr class="${rowClass}">
                    <td style="font-family:'IBM Plex Mono',monospace;font-size:13px;color:#FFFFFF;font-weight:600;">${d.device_id}</td>
                    <td>${statusBadge}</td>
                    <td>${piholeBadge}</td>
                    <td style="font-family:'IBM Plex Mono',monospace;font-size:12px;color:#9CA3AF">${d.tailscale_ip || 'Sin configurar'}</td>
                    <td style="color:#9CA3AF;font-size:12px">${d.time_ago}</td>
                </tr>`;
            });

            document.getElementById('tableBody').innerHTML = html || '<tr><td colspan="5" style="text-align:center;color:#9CA3AF;padding:40px">Sin dispositivos en flota</td></tr>';
            
            document.getElementById('st-total').innerText = devices.length;
            document.getElementById('st-online').innerText = tOnline;
            document.getElementById('st-alerts').innerText = tAlerts;
            document.getElementById('st-premium').innerText = tPrem;
        }

        if (localStorage.getItem('soc_auth')) {
            showDashboard();
            fetchData();
        }
    </script>
</body>
</html>"""
    return html_content

@app.get("/")
def root():
    return {"service": "SafeLock Telemetry", "status": "active", "version": "1.3.0"}
