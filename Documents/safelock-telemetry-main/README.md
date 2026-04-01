# SafeLock Telemetry Server

Servidor central de telemetría para SafeLock SoC.

## Endpoints

- `POST /heartbeat` — recibe heartbeat de cada SafeLock
- `GET /devices` — lista todos los dispositivos con su estado
- `GET /dashboard?x_api_secret=KEY` — dashboard visual interno

## Variables de entorno

- `API_SECRET` — clave secreta para autenticación (default: openlock2026)
