# Strix frontal

Consola web + API para lanzar escaneos de Strix a través de Kafka y revisar los
resultados. El frontal **no ejecuta Strix**: publica la petición y el orquestador
(`k8s/kafka_orchestrator.py`, un Job de KEDA por petición) hace el escaneo.

```
navegador ─► frontal ──audit.request──► orquestador (KEDA) ──► Strix
             frontal ◄──audit.status─── "running" al aceptar la petición
             frontal ◄──audit.result─── resultado + claves de MinIO
             frontal ◄──── MinIO ────── informe, PoCs, transcript del agente
```

## Qué hace

- **Nuevo escaneo**: eliges activo/target, tipo de prueba (plantillas de
  instrucción: completo, OWASP Top 10, prueba dirigida, authz, inyecciones,
  API, revisión de código), profundidad, instrucción y presupuesto. Ves el JSON
  exacto que se va a publicar antes de lanzarlo.
- **Builder de instrucciones** (`#/instructions`): rellena las seis plantillas del
  generador V9 (`app/instructions/*.md`) con un formulario: Web, API, Autorización y
  sus variantes ampliadas (`web-exp`, `api-exp`, `auth-exp`). Los `{{SELECT_*}}` salen
  de `app/instructions/catalogs.json` y los `{{TEXT_*}}` se describen en
  `app/instructions/fields.json`. Cada opción de un `SELECT_` aporta su frase
  (`instruction`) al texto final, no su id; las selecciones ordenadas van numeradas
  (`1) …; 2) …`) y el texto libre del catálogo se añade al final. Las selecciones son
  obligatorias (N/A solo con motivo); los campos de texto son opcionales y, si se dejan
  vacíos, desaparece la línea que los contiene. Los campos comunes se conservan al
  cambiar de plantilla y los valores se guardan en el navegador; si el servidor detecta
  un posible secreto (JWT, bearer, clave privada, `password=…`) ese campo no se persiste
  y hay que confirmar antes de copiar, descargar o usar la instrucción. El texto resultante se
  copia, se descarga como `.md` (para `--instruction-file`) o se pasa al wizard de
  escaneo con la instrucción y el modo ya puestos; también está embebido en el wizard
  de «Nuevo escaneo» (paso 4, pestaña Builder), compartiendo el mismo estado. Lo renderiza el servidor
  (`POST /manage/instruction-builder/render`), que deja como `{{X}}` los huecos y los
  devuelve en `issues`.
- **Resultados**: estado en vivo, hallazgos con descripción, PoC, evidencia y
  remediación; el informe del pentest; y el visor oficial de Strix con la
  ejecución de los agentes (`/runs/<id>`). Cómo se integra y cómo mantenerlo:
  [`VISOR_STRIX.md`](VISOR_STRIX.md).
- **Retest**: de un hallazgo, de los de un escaneo, de una selección o de todo lo
  abierto de un activo. El agente reproduce la PoC original y da un veredicto
  (`sigue vulnerable` / `corregida` / `no concluyente`), que se aplica solo.
- **Triage**: abierta / corregida / riesgo aceptado / falso positivo. Los
  hallazgos se correlacionan entre escaneos (CWE + método + endpoint).
- **Relanzar** un escaneo con la misma configuración.
- **Escaneos externos**: lo que lances a mano con `kafka-console-producer`
  también aparece (tipo "Externo"), agrupado por target.

## El mensaje

Es el mismo que escribes a mano, más un id generado y dos campos que el
orquestador ignora (`kind`, `source`):

```json
{"id": "frontal-12-3fa9c1d2", "target": "http://juice-shop:3000", "scan_mode": "quick",
 "max_budget": 2, "instruction": "...", "kind": "scan", "source": "strix-frontal"}
```

El orquestador devuelve la petición dentro de `audit.result` (`request.id`), y así
se asocia el resultado al escaneo.

## Local

Solo el frontal y el builder de instrucciones, sin Docker ni Kafka
(datos desechables en `/tmp`, el consumidor de Kafka reintenta en segundo plano):

```bash
./demo/run-builder.sh             # http://127.0.0.1:8160
./demo/run-builder.sh 8161        # en otro puerto
```

Todo el builder funciona: rellenar, render en vivo, copiar, descargar `.md`,
verlo en el wizard y la vista previa del mensaje. Lo único que falla es lanzar
el escaneo (no hay Kafka), con el error claro de "No se pudo publicar en Kafka".

Todo el flujo en tu máquina, con el orquestador real y Strix real:

```bash
./demo/run-audit-local.sh            # desde WSL sin integración: DOCKER=docker.exe ./demo/run-audit-local.sh
./demo/run-audit-local.sh down       # parar los contenedores (los datos se conservan)
```

- Docker (`demo/docker-compose.dev.yml` + `demo/docker-compose.audit.yml`, proyecto
  `demo`): Kafka, MinIO, Juice Shop y el frontal en **http://localhost:8000**.
- Host: `k8s/kafka_orchestrator.py` en bucle (hace de KEDA: un mensaje por
  ejecución) con Strix y su sandbox Docker. Dentro del sandbox, `juice-shop`
  apunta al host (`STRIX_DOCKER_EXTRA_HOSTS`), así que los targets se escriben
  como en el clúster: `http://juice-shop:3000`. Para más nombres:
  `AUDIT_TARGET_HOSTS="juice-shop mi-app"` (con su puerto publicado en el host).
- El LLM sale de `~/.strix/cli-config.json`. `demo/audit/strix_local_boot.py`
  sustituye al módulo que trae la imagen del orquestador.
- También puedes lanzar a mano, como en el clúster:
  `docker exec -i demo-kafka-1 /opt/kafka/bin/kafka-console-producer.sh --bootstrap-server localhost:9092 --topic audit.request`

Tests: `uv run pytest tests/test_frontal_audit.py tests/test_instruction_builder.py`.

## Kubernetes

```bash
docker build -f frontal/Dockerfile -t registry-lab.sia.es/inditex-strix/strix-frontal:0.1.0 .
docker push registry-lab.sia.es/inditex-strix/strix-frontal:0.1.0
kubectl apply -f k8s/frontal.yaml
kubectl -n strix-apps port-forward svc/strix-frontal 8000:80
```

Usa el mismo Secret `minio-secret` que el orquestador. Para el estado
"en ejecución", el orquestador desplegado tiene que incluir `_publish_running`
(redespliega `k8s/kafka-orchestrator.configmap.yaml`); sin eso, los escaneos pasan
de "en cola" a "completado" directamente.

## Configuración

| Variable | Por defecto | |
|---|---|---|
| `FRONTAL_KAFKA_BOOTSTRAP` | `localhost:9092` | |
| `FRONTAL_KAFKA_GROUP` | `strix-frontal` | grupo del consumidor de resultados |
| `FRONTAL_KAFKA_TOPIC_AUDIT_REQUEST` / `_RESULT` / `_STATUS` | `audit.request` / `audit.result` / `audit.status` | |
| `FRONTAL_DATABASE_URL` | Postgres en localhost | `sqlite:////data/frontal.db` en la imagen |
| `FRONTAL_ARTIFACTS_DIR` | `./frontal_data` | caché local de los runs bajados de MinIO |
| `MINIO_ENDPOINT`, `MINIO_ACCESS_KEY`, `MINIO_SECRET_KEY` | | también `FRONTAL_S3_*` |
| `FRONTAL_MAX_BUDGET_USD` | sin límite | presupuesto que aparece por defecto en el formulario |
| `FRONTAL_IMPORT_EXTERNAL_RESULTS` | `true` | importar resultados de peticiones manuales |

## Interfaz

`app/console.html` es un único fichero autocontenido (sin CDN: tiene que funcionar
en un clúster aislado) y sigue el tema claro de **Sewing IOP DS**, el design system
corporativo que usa el frontal React (`spa-strixweb`). Los tokens están inlineados
en el bloque `:root` con el nombre de origen en cada comentario
(`--ids-color-bg-default`, `--ids-comp-button-primary-default`, `--ids-size-radius-rounded`…),
así que para cambiar el aspecto basta con tocar esas variables:

- Fondo `#fff`, texto `#000`, texto secundario `#757575`, fondo bajo `#f7f7f7`,
  borde `#e3e3e3` y foco `#0170e9`.
- Tipografía Helvetica Now Text; cuerpo 14/22, labels 13/20 en mayúsculas, títulos
  20/28 y 24/32. Radios de 4 px.
- Botón primario negro (`#000`, hover `#434343`) con texto en mayúsculas; botón
  secundario con borde gris medio y fondo bajo al pasar el cursor; campos
  subrayados de 40 px de alto con foco azul de 2 px.
- Los KPI del dashboard replican el `ids-kpi` corporativo: indicador de 24×3 px
  bajo el label (rojo cuando hay vulnerabilidades abiertas) y valor en 32/40.
- Las tarjetas y los chips siguen los patrones `ids-card` e `ids-option-picker`:
  hover por líneas interiores en las tarjetas, contorno fino y fondo bajo en los
  chips seleccionables, y las filas de tabla clicables se sombreaden al pasar.
- Etiquetas de severidad con un cuadrado del color del nivel delante (el hueco
  del icono de `ids-tag`); los colores son los del frontal corporativo:
  `#b3261e` crítica, `#e8710a` alta, `#b58900` media, `#1a73e8` baja,
  `#188038` corregida y `#5f6368` informativa.

IOP DS también tiene tema oscuro (fondo `#000`, texto `#fff`, borde `#5e5e5e`); si
alguna vez hace falta, es sustituir los tokens de `:root`, no reescribir el CSS.

## Limitaciones

- **Sin autenticación.** Ponlo detrás de SSO/oauth2-proxy antes de exponerlo.
- **No se pueden cancelar escaneos**: el orquestador hace commit antes de escanear.
  Por la misma razón, si un pod muere no llega resultado; el escaneo se queda
  "en ejecución" hasta que lo marcas como fallido desde la UI.
- `runner.py`, `worker.py`, `launcher.py`, `app/launcher.py`, `app/consumer.py`,
  `app/messaging.py` y `app/scan_exec.py` son del diseño anterior
  (`scan.requests`/`scan.results`) y la app ya no los usa.
