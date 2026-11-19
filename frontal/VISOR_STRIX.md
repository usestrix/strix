# El visor de Strix dentro del frontal

Guía de mantenimiento: de dónde sale el visor (`strix view`), cómo llegan los
ficheros de un run hasta él y qué revisar cuando se actualiza Strix.

## En una frase

El frontal **no ejecuta `strix view`**. Reutiliza el SPA ya compilado que trae el
paquete de Strix (`strix/interface/viewer/static/`) **sin modificarlo**, y
reimplementa en FastAPI los endpoints JSON que ese SPA consume
(`frontal/app/viewer_api.py`), leyendo los runs del almacén de artefactos del
frontal en lugar del `./strix_runs` local.

¿Por qué no lanzar `strix view` y hacer de proxy? Porque el servidor original
lee **un único** directorio de run del disco local y bloquea el historial y los
informes detrás de una verificación por email (OTP) contra el relay de Strix.
Reimplementar los endpoints evita las dos cosas y permite direccionar los runs
por **id de escaneo** del frontal, no por el nombre de run que genera la CLI.

## Flujo de extremo a extremo

```
 Job KEDA (k8s/kafka_orchestrator.py)
   │ 1. Strix termina → strix_runs/<run_name>/ (run.json, vulnerabilities.json,
   │    penetration_test_report.md, .state/agents.json, .state/agents.db, ...)
   │ 2. upload_run_artifacts(): sube TODO el árbol (rglob, incluye .state/)
   │    a GridFS (MONGO_URI) o a MinIO (MINIO_ENDPOINT)
   │ 3. publica audit.result con "storage": {uploaded, backend, bucket, prefix}
   ▼
 Backend frontal (frontal/app, FastAPI)
   │ 4. AuditResultConsumer → apply_result() → _localize_run()      [audit.py]
   │    → store.download_prefix() copia el run a
   │      $FRONTAL_ARTIFACTS_DIR/runs/<scan_id>/                    [artifacts.py]
   │ 5. si existe run.json: scan.artifact_path = "runs/<scan_id>" e ingest_run()
   ▼
 Navegador
   │ 6. console.html pinta "Ver ejecución del agente ↗" → /runs/<scan_id>
   │    solo si scan.has_artifacts && config.viewer_available
   │ 7. nginx (Dockerfile.frontend) pasa /runs/* y /api/* al backend tal cual
   │ 8. GET /runs/<scan_id> → viewer_spa(): devuelve static/index.html y fija
   │    la cookie frontal_run=<scan_id>
   │ 9. el SPA pide ./assets/... → /runs/assets/... (servido por viewer_spa)
   │10. el SPA llama /api/run, /api/transcript, ... → viewer_api.py resuelve el
   │    scan (por ?run= o por la cookie) y lee los ficheros con los helpers de
   │    strix.interface.viewer.transcript
```

### Paso 4: de dónde se descarga el run

`_localize_run()` (`frontal/app/audit.py`) decide según el evento `audit.result`:

| `storage` en el evento | `FRONTAL_ARTIFACT_STORE` | Qué hace |
|---|---|---|
| `uploaded: true`, `backend: mongo` | `mongo` | `MongoArtifactStore.download_prefix()`: baja los ficheros GridFS con `metadata.run == prefix` |
| `uploaded: true`, `backend: s3` (o sin `backend`, orquestadores antiguos) | `s3` | `S3ArtifactStore.download_prefix()`: baja `s3://bucket/prefix/*` |
| `uploaded: true` pero el backend **no coincide** | cualquiera | Warning en el log y **solo resumen**: no hay visor para ese escaneo |
| `uploaded: false` + `run_dir` accesible | cualquiera | copia el directorio (solo si ambos pods comparten volumen) |

Si no queda un `run.json` en `runs/<scan_id>/`, `artifact_path` se queda a
`None`, `has_artifacts` es `false` y la consola no muestra el botón del visor.

Las dos descargas validan que cada nombre de fichero (dato de la BD/bucket) no
escape de `runs/<scan_id>/` (`_safe_target`, comprobación de `parents`).

### Pasos 8–10: cómo sabe el SPA qué run mostrar

El SPA está compilado con `base: "./"` (`frontend/vite.config.ts`), así que sus
assets son relativos y funcionan bajo `/runs/`. Pero sus llamadas de datos son
**absolutas** (`/api/run`) y la primera no lleva `?run=`. Como el bundle no se
toca, el frontal usa una cookie:

1. `GET /runs/42` → `viewer_spa()` devuelve `index.html` y pone
   `frontal_run=42` (`httponly`, `samesite=strict`, `path=/`).
2. `GET /api/run` (sin `?run=`) → `_resolve_scan()` usa la cookie → scan 42.
3. Si el usuario cambia de run en el historial, el SPA manda `?run=<name>`;
   `name` es el id del escaneo en texto (lo que devuelve `/api/runs`), así que
   `?run=` tiene prioridad sobre la cookie.
4. Sin `?run=` ni cookie válida → el último escaneo con artefactos.

`_run_dir()` resuelve `artifacts_dir / scan.artifact_path` y rechaza cualquier
ruta fuera de `artifacts_dir` o sin `run.json` (→ 404 `run artifacts unavailable`).

## Contrato de endpoints

Los payloads replican exactamente los de `strix/interface/viewer/server.py`.

| Endpoint | Upstream (`strix view`) | Frontal (`viewer_api.py`) |
|---|---|---|
| `GET /api/capabilities` | `can_steer` si hay scan vivo | siempre `{"can_steer": false}` |
| `GET /api/auth/status` | estado OTP real | siempre `{"verified": true, "email": null}` → historial desbloqueado |
| `GET /api/runs` | runs de `./strix_runs`, bloqueados sin OTP | últimos 100 `Scan` con `artifact_path`; `name` = id del escaneo |
| `GET /api/run` | `run.json` + `finished` | igual (`read_run_summary`) |
| `GET /api/vulnerabilities` | `vulnerabilities.json` | igual (`read_vulnerabilities`) |
| `GET /api/report` | `penetration_test_report.md` | igual (`read_report_markdown`) |
| `GET /api/transcript` | grafo de agentes + eventos | igual (`build_run_state`) |
| `POST /api/event` | telemetría al relay | 204, se descarta |
| `POST /api/feedback` | relay | 404 `unavailable` |
| `POST /api/report/send` | sube el PDF al relay | 404 `unavailable` (los informes no salen) |
| `POST /api/agents/steer` | steering del scan vivo | 403 `steering_unavailable` |
| `POST /api/auth/otp/*`, `/api/auth/forget` | flujo OTP | **no implementados** (404): el SPA no los llama porque `auth/status` ya dice `verified` |
| `GET /runs/{path}` | — | assets del bundle o `index.html` + cookie |

Ojo con el espacio de nombres: **`/api/*` y `/runs/*` son del visor**. La API
propia del frontal vive en `/manage/*`; no añadas rutas propias bajo `/api/`.

### Ficheros del run que necesita cada vista

| Fichero (dentro de `runs/<scan_id>/`) | Lo lee | Vista |
|---|---|---|
| `run.json` | `read_run_summary`, `primary_target` | Overview, historial; **obligatorio** |
| `vulnerabilities.json` | `read_vulnerabilities`, `severity_counts` | Vulnerabilities, recuento por severidad |
| `penetration_test_report.md` | `read_report_markdown` | Report |
| `.state/agents.json` | `TuiLiveView.hydrate_from_run_dir` | Grafo de agentes |
| `.state/agents.db` (SQLite, solo lectura) | `strix.interface.tui.history.load_session_history` | Transcript de cada agente |

Si falta `.state/`, el visor carga pero el grafo y el transcript salen vacíos.

## Cómo entra en la imagen

- `frontal/Dockerfile` instala Strix **editable** desde `/opt/strix-src`
  (`pip install -e`). Editable a propósito: el build normal ejecuta
  `scripts/tui_sidecar_hook.py`, que compila la TUI en Go; en editable no hace
  nada. `bundle_dir()` apunta entonces a `/opt/strix-src/strix/interface/viewer/static`.
- `frontal/Dockerfile.dockerignore` incluye `strix/` pero excluye
  `strix/interface/viewer/frontend/` (fuentes + `node_modules`): solo viaja el
  bundle compilado de `static/`.
- `frontal/app/main.py` importa `viewer_api` dentro de un `try/except ImportError`.
  Si falla (imagen sin Strix o un cambio upstream rompe un import), el frontal
  arranca igual, loguea `Strix viewer unavailable (...)`, no registra las rutas
  y `/manage/config` devuelve `viewer_available: false` (la consola oculta el
  botón). **Un fallo aquí es silencioso salvo por ese warning.**
- `Dockerfile.frontend` (nginx) no contiene nada del visor: todo lo que no es
  `/` ni `/frontend-health` se reenvía al backend (`location /`).
- El caché de runs vive en `/data/artifacts` (PVC `strix-frontal-data`, RWO,
  por eso `replicas: 1` en `k8s/frontal.yaml`).

## Mantenimiento

### Al actualizar Strix (merge de upstream)

Todo lo que el frontal toma de Strix está en estos imports de `viewer_api.py`:

```python
from strix.interface.viewer.server import bundle_dir
from strix.interface.viewer.transcript import (
    build_run_state, primary_target, read_report_markdown,
    read_run_summary, read_vulnerabilities, severity_counts,
)
```

Checklist:

1. **¿Siguen existiendo esos símbolos?**
   ```bash
   uv run --with-requirements frontal/requirements.txt python -c "import frontal.app.viewer_api"
   ```
   Si falla, el visor desaparecería en silencio en la imagen (ver arriba).
2. **¿El SPA llama a algún endpoint nuevo?** Compara lo que pide el bundle con
   lo que implementa el frontal:
   ```bash
   diff <(grep -ohE '"/api/[a-z/_]+' strix/interface/viewer/static/assets/index-*.js | tr -d '"' | sort -u) \
        <(grep -ohE '@router\.(get|post)\("/api/[^"]+' frontal/app/viewer_api.py | sed 's/.*("//' | sort -u)
   ```
   Hoy solo deben salir `/api/auth/forget` y `/api/auth/otp/{start,verify}`
   (no implementados a propósito). Cualquier otro es un endpoint nuevo: míralo
   en `_handle_api` / `do_POST` de `strix/interface/viewer/server.py` y añádelo
   a `viewer_api.py` con el mismo payload.
3. **¿Cambió la forma de algún payload?** Revisa el diff de upstream:
   ```bash
   git diff <rev_anterior>..HEAD -- strix/interface/viewer/server.py strix/interface/viewer/transcript.py
   ```
   Fíjate sobre todo en `run_list_entry()` (forma de cada entrada de
   `/api/runs`, que `runs()` replica a mano) y en `build_runs_payload()`.
4. **¿Cambiaron los ficheros del run?** (`strix/core/paths.py`:
   `RUN_RECORD_FILENAME`, `RUNTIME_STATE_DIR_NAME`; nombres en `transcript.py`
   y `tui/history.py`). Los runs ya cacheados en `/data/artifacts` son de la
   versión anterior; los helpers toleran ficheros ausentes pero no formatos nuevos.
5. **¿Cambió el arranque del SPA?** Si upstream deja de usar `base: "./"`, los
   assets bajo `/runs/` dejarían de resolver; si empieza a leer el run de la URL
   en lugar de `?run=`, revisa la lógica de la cookie.
6. Reconstruye la imagen del backend y haz la prueba manual de abajo.

### Recompilar el SPA

No hace falta: el bundle compilado está commiteado en
`strix/interface/viewer/static/` y viene con cada versión de Strix. Solo si se
modificara el SPA (evítalo; el diseño es no tocarlo):

```bash
cd strix/interface/viewer/frontend && npm ci && npm run build   # escribe en ../static
```

### Añadir o cambiar un endpoint

- Mantén el payload idéntico al de `server.py`: el SPA es de upstream y no se toca.
- Si el endpoint es por run, usa `_resolve_scan(session, settings, run, frontal_run)`
  con los mismos parámetros `run` (query) y `frontal_run` (cookie) que el resto.
- Si upstream envía algo fuera (relay, email, telemetría), respóndelo en local
  sin reenviar nada, como `/api/event` o `/api/report/send`.

## Prueba manual

Con el backend levantado (`demo/run-frontal.sh`, puerto 8000) y al menos un
escaneo con artefactos (id `42` en el ejemplo):

```bash
curl -s localhost:8000/manage/config | jq .viewer_available         # true
curl -s localhost:8000/api/runs | jq '.runs[] | {name, status}'      # aparece "42"
curl -s 'localhost:8000/api/run?run=42' | jq '{status, finished}'
curl -s 'localhost:8000/api/transcript?run=42' | jq '.agents | length'   # > 0
curl -si localhost:8000/runs/42 | grep -i set-cookie                 # frontal_run=42
```

Y en el navegador: botón "Ver ejecución del agente ↗" de un escaneo terminado →
debe abrir el visor con grafo, transcript, vulnerabilidades e informe.

`viewer_api.py` no tiene tests propios hoy; `tests/test_frontal_audit.py` cubre
la parte de descarga (GridFS ida y vuelta, rutas que intentan escapar).

## Diagnóstico

| Síntoma | Causa probable | Dónde mirar |
|---|---|---|
| No sale el botón del visor en ningún escaneo | `viewer_available: false`: falló el import | log del backend: `Strix viewer unavailable` |
| No sale el botón en un escaneo concreto | `artifact_path` vacío: no se descargó el run o no tenía `run.json` | log: `artifacts are in '...' storage but FRONTAL_ARTIFACT_STORE is '...'` o `artifact download failed`; `storage` en `scan.result` |
| `503 viewer bundle not built` en `/runs/<id>` | falta `static/index.html` en el paquete instalado | `ls /opt/strix-src/strix/interface/viewer/static` en el pod |
| `404 run artifacts unavailable` | el escaneo tiene `artifact_path` pero el directorio no está en disco (PVC nuevo o borrado) | `ls /data/artifacts/runs/<id>` |
| El visor carga, pero grafo/transcript vacíos | no se subió/bajó `.state/` | `.state/agents.json` y `.state/agents.db` en el run local y en GridFS/MinIO |
| Pantalla en blanco, assets 404 | el SPA se sirve fuera de `/runs/` o upstream cambió `base` | pestaña Network: los assets deben ir a `/runs/assets/...` |
| El visor muestra otro escaneo | la cookie `frontal_run` es por navegador, no por pestaña (ver limitaciones) | recargar `/runs/<id>` |

## Limitaciones conocidas

- **Sin re-descarga bajo demanda.** El run se baja una sola vez, al procesar
  `audit.result`. Si se pierde `/data` (PVC nuevo, cambio de cluster), los
  escaneos antiguos conservan `artifact_path` en la BD pero dan 404 en el visor
  aunque sigan en GridFS/MinIO. Arreglo posible: en `_run_dir()`, si falta el
  directorio, llamar a `get_artifact_store(settings).localize(scan.id, ...)`.
- **El caché no se purga.** `/data/artifacts/runs/` crece con cada escaneo.
- **Cookie compartida entre pestañas.** Abrir dos escaneos a la vez en el mismo
  navegador: la segunda pestaña pisa la cookie y la primera, si aún no había
  hecho su primera carga, puede mostrar el segundo run. Como los runs del
  frontal siempre están terminados, el SPA hace una carga y deja de sondear,
  así que en la práctica solo afecta a la carga inicial.
- **Sin steering ni envío de informes** (por diseño: el scan corre en otro pod y
  nada sale hacia el relay de Strix).
- **Una réplica.** El PVC es RWO; más réplicas necesitan `/data` en un volumen RWX.
- **Sin control de acceso propio.** Cualquiera que llegue al frontal puede leer
  cualquier run por `/api/*?run=<id>`; el upstream protegía con token + OTP, aquí
  la protección es la del Ingress/red delante del frontal.
