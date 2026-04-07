from fastapi import FastAPI, Header, HTTPException, Depends
from fastapi.responses import HTMLResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from pydantic import BaseModel
from datetime import datetime, timezone
import os
import httpx
import secrets

app = FastAPI(title="SafeLock Telemetry SOC")

# --- Configuración ---
API_SECRET = os.environ.get("API_SECRET", "openlock2026")
SUPABASE_URL = os.environ.get("SUPABASE_URL")
SUPABASE_KEY = os.environ.get("SUPABASE_KEY")

security = HTTPBasic()

def sb_headers():
    return {
        "apikey": SUPABASE_KEY,
        "Authorization": f"Bearer {SUPABASE_KEY}",
        "Content-Type": "application/json",
        "Prefer": "resolution=merge-duplicates"  # Crucial para que funcione el POST con conflicto
    }

# --- Seguridad ---
def verificar_acceso_dashboard(credentials: HTTPBasicCredentials = Depends(security)):
    usuario_correcto = secrets.compare_digest(credentials.username, "admin")
    clave_correcta = secrets.compare_digest(credentials.password, API_SECRET)
    if not (usuario_correcto and clave_correcta):
        raise HTTPException(
            status_code=401,
            detail="Acceso denegado",
            headers={"WWW-Authenticate": "Basic"},
        )
    return credentials.username

# --- Modelos ---
class Heartbeat(BaseModel):
    device_id: str
    pihole_active: bool
    tailscale_ip: str = ""
    version: str = "1.0"
    critical_alert: bool = False

class DeviceMetadataUpdate(BaseModel):
    display_name: str = ""
    label: str = ""

# --- Endpoints API ---

@app.get("/")
def root():
    return {"service": "SafeLock Telemetry", "status": "active", "version": "1.3.2"}

@app.post("/heartbeat")
async def heartbeat(data: Heartbeat, x_api_secret: str = Header(None)):
    if x_api_secret != API_SECRET:
        raise HTTPException(status_code=401, detail="Unauthorized")
    
    payload = {
        **data.model_dump(),
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
            f"{SUPABASE_URL}/rest/v1/devices?select=*&limit=500",
            headers=sb_headers()
        )
    if r.status_code != 200:
        raise HTTPException(status_code=500, detail=f"Error Supabase: {r.text}")
    return {"devices": r.json()}

@app.get("/api/auth-check")
async def auth_check(username: str = Depends(verificar_acceso_dashboard)):
    return {"ok": True, "user": username}

@app.post("/api/device-metadata/{device_id}")
async def update_device_metadata(
    device_id: str,
    data: DeviceMetadataUpdate,
    username: str = Depends(verificar_acceso_dashboard),
):
    payload = {
        "device_id": device_id,
        "display_name": data.display_name.strip(),
        "label": data.label.strip(),
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }
    
    async with httpx.AsyncClient() as client:
        # Usamos POST con resolution=merge-duplicates para actualizar solo columnas enviadas
        r = await client.post(
            f"{SUPABASE_URL}/rest/v1/devices?on_conflict=device_id",
            headers=sb_headers(),
            json=payload
        )
    
    if r.status_code not in [200, 201, 204]:
        # Log del error para depuración
        print(f"DEBUG Supabase Error: {r.text}")
        raise HTTPException(status_code=r.status_code, detail=r.text)
    
    return {"ok": True}

# --- Dashboard HTML ---
@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard_ui():
    # Solo he actualizado la función saveMetadata en el JS para mostrar errores reales
    html_content = """
    <!DOCTYPE html>
    <html lang="es">
    <!-- ... (Todo tu CSS igual) ... -->
    <style>
        @import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@400;500;600&family=IBM+Plex+Mono:wght@400;600;700&display=swap');
        body { background: #050608; color: #D1D5DB; font-family: 'IBM Plex Sans', sans-serif; padding: 0; margin: 0; }
        * { box-sizing: border-box; }
        #login-view { height: 100vh; display: flex; align-items: center; justify-content: center; }
        .login-box { background: #121417; padding: 40px; border-radius: 12px; border: 1px solid #333; width: 100%; max-width: 360px; text-align: center; }
        .login-box h2 { color: #29B5B5; font-family: 'IBM Plex Mono', monospace; }
        .login-box input { width: 100%; padding: 12px; margin-bottom: 16px; background: #08090A; border: 1px solid #333; color: #fff; border-radius: 6px; }
        .login-box button { width: 100%; padding: 14px; background: #29B5B5; color: #000; border: none; border-radius: 6px; font-weight: bold; cursor: pointer; }
        #dashboard-view { display: none; padding: 32px; max-width: 1200px; margin: 0 auto; }
        .header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 32px; }
        h1 { color: #29B5B5; font-family: 'IBM Plex Mono', monospace; }
        .stats { display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin-bottom: 32px; }
        .stat { background: #121417; border: 1px solid #444; padding: 20px; border-left: 4px solid #444; }
        .stat .val { font-size: 32px; font-family: 'IBM Plex Mono', monospace; color: #fff; }
        .search-box { width: 100%; max-width: 400px; padding: 12px; background: #121417; border: 1px solid #444; border-radius: 6px; color: #fff; margin-bottom: 20px; }
        table { width: 100%; border-collapse: collapse; background: #121417; border: 1px solid #444; }
        th { background: #08090A; padding: 14px; text-align: left; font-size: 10px; color: #9CA3AF; text-transform: uppercase; border-bottom: 1px solid #444; }
        td { padding: 14px; border-bottom: 1px solid #252A30; font-size: 13px; }
        .badge { padding: 4px 8px; border-radius: 4px; font-size: 10px; font-weight: 700; }
        .bg-green { background: rgba(16, 185, 129, 0.15); color: #10B981; border: 1px solid rgba(16, 185, 129, 0.3); }
        .bg-red { background: rgba(239, 68, 68, 0.15); color: #EF4444; border: 1px solid rgba(239, 68, 68, 0.3); }
        .modal-backdrop { position: fixed; inset: 0; background: rgba(0,0,0,0.8); display: none; align-items: center; justify-content: center; }
        .modal-backdrop.open { display: flex; }
        .modal-card { background: #121417; padding: 24px; border-radius: 12px; width: 400px; border: 1px solid #333; }
        .modal-error { color: #EF4444; font-size: 12px; margin-top: 10px; }
        .btn-meta { background: transparent; border: 1px solid #3A4048; color: #D1D5DB; padding: 6px 12px; border-radius: 4px; cursor: pointer; }
    </style>
    <body>
        <!-- LOGIN VIEW -->
        <div id="login-view">
            <form class="login-box" onsubmit="handleLogin(event)">
                <h2>🔒 SafeLock SOC</h2>
                <input type="text" id="user" placeholder="Usuario" required>
                <input type="password" id="pass" placeholder="Contraseña" required>
                <button type="submit" id="loginBtn">Ingresar</button>
                <div id="loginError" class="error-msg" style="display:none; color:red;"></div>
            </form>
        </div>

        <!-- DASHBOARD VIEW -->
        <div id="dashboard-view">
            <div class="header">
                <h1>🔒 OpenLock Telemetry</h1>
                <button onclick="fetchData()" id="refreshBtn">Actualizar</button>
            </div>
            <div class="stats">
                <div class="stat"><div class="val" id="st-total">0</div><div class="lbl">Total</div></div>
                <div class="stat"><div class="val" id="st-online">0</div><div class="lbl">Online</div></div>
                <div class="stat"><div class="val" id="st-alerts">0</div><div class="lbl">Alertas</div></div>
                <div class="stat"><div class="val" id="st-premium">0</div><div class="lbl">Premium</div></div>
            </div>
            <input type="text" id="searchBox" class="search-box" onkeyup="filterTable()" placeholder="Buscar...">
            <table>
                <thead>
                    <tr>
                        <th>ID</th><th>Nombre</th><th>Etiqueta</th><th>Salud</th><th>PiHole</th><th>IP</th><th>Visto</th><th>Acción</th>
                    </tr>
                </thead>
                <tbody id="tableBody"></tbody>
            </table>
        </div>

        <!-- MODAL -->
        <div id="metadataModal" class="modal-backdrop">
            <div class="modal-card">
                <h3>Editar Dispositivo</h3>
                <p id="modalDeviceId" style="font-family:monospace; color:#29B5B5"></p>
                <input type="text" id="deviceNameInput" placeholder="Nombre">
                <input type="text" id="deviceLabelInput" placeholder="Etiqueta">
                <div id="metadataError" class="modal-error"></div>
                <div style="display:flex; gap:10px; margin-top:20px;">
                    <button onclick="closeMetadataModal()">Cancelar</button>
                    <button id="saveMetadataBtn" onclick="saveMetadata()" style="background:#29B5B5; color:#000; border:none; padding:8px; border-radius:4px; cursor:pointer;">Guardar</button>
                </div>
            </div>
        </div>

        <script>
            let fleetDevices = [];
            let activeDeviceId = null;

            function handleLogin(e) {
                e.preventDefault();
                const u = document.getElementById('user').value;
                const p = document.getElementById('pass').value;
                const token = btoa(u + ':' + p);
                fetch('/api/auth-check', { headers: { 'Authorization': 'Basic ' + token } })
                    .then(res => res.ok ? (localStorage.setItem('soc_auth', token), showDashboard(), fetchData()) : alert('Error'))
            }

            function showDashboard() {
                document.getElementById('login-view').style.display = 'none';
                document.getElementById('dashboard-view').style.display = 'block';
            }

            function fetchData() {
                const token = localStorage.getItem('soc_auth');
                fetch('/api/fleet', { headers: { 'Authorization': 'Basic ' + token } })
                    .then(res => res.json())
                    .then(data => {
                        fleetDevices = data.devices;
                        renderTable(fleetDevices);
                        updateStats();
                    });
            }

            function updateStats() {
                document.getElementById('st-total').innerText = fleetDevices.length;
                document.getElementById('st-online').innerText = fleetDevices.filter(d => d.status === 'online').length;
                document.getElementById('st-alerts').innerText = fleetDevices.filter(d => d.critical_alert).length;
                document.getElementById('st-premium').innerText = fleetDevices.filter(d => d.pihole_active).length;
            }

            function renderTable(devices) {
                let html = "";
                devices.forEach(d => {
                    html += `<tr>
                        <td>${d.device_id}</td>
                        <td>${d.display_name || '---'}</td>
                        <td>${d.label || '---'}</td>
                        <td><span class="badge ${d.critical_alert ? 'bg-red' : 'bg-green'}">${d.critical_alert ? 'ALERTA' : 'OK'}</span></td>
                        <td>${d.pihole_active ? '✅' : '❌'}</td>
                        <td>${d.tailscale_ip}</td>
                        <td>${d.last_seen ? d.last_seen.split('T')[1].substring(0,5) : '---'}</td>
                        <td><button class="btn-meta" onclick="openMetadataModal('${d.device_id}')">Editar</button></td>
                    </tr>`;
                });
                document.getElementById('tableBody').innerHTML = html;
            }

            function openMetadataModal(id) {
                activeDeviceId = id;
                const d = fleetDevices.find(x => x.device_id === id);
                document.getElementById('modalDeviceId').innerText = id;
                document.getElementById('deviceNameInput').value = d.display_name || '';
                document.getElementById('deviceLabelInput').value = d.label || '';
                document.getElementById('metadataModal').classList.add('open');
            }

            function closeMetadataModal() {
                document.getElementById('metadataModal').classList.remove('open');
            }

            function saveMetadata() {
                const token = localStorage.getItem('soc_auth');
                const btn = document.getElementById('saveMetadataBtn');
                const err = document.getElementById('metadataError');
                
                btn.disabled = true;
                err.innerText = "";

                fetch('/api/device-metadata/' + activeDeviceId, {
                    method: 'POST',
                    headers: { 
                        'Authorization': 'Basic ' + token,
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({
                        display_name: document.getElementById('deviceNameInput').value,
                        label: document.getElementById('deviceLabelInput').value
                    })
                })
                .then(async res => {
                    if (!res.ok) {
                        const detail = await res.json();
                        throw new Error(detail.detail || 'Error desconocido');
                    }
                    return res.json();
                })
                .then(() => {
                    closeMetadataModal();
                    fetchData();
                })
                .catch(e => {
                    err.innerText = "Error: " + e.message;
                    console.error(e);
                })
                .finally(() => btn.disabled = false);
            }
        </script>
    </body>
    </html>
    """
    return html_content
