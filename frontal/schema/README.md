# Esquemas de base de datos

Las aplicaciones crean sus tablas, colecciones e índices solas al arrancar o al usarlas. Estos ficheros son
para cuando eso no es posible o no se quiere: un usuario sin permisos de DDL, o un DBA que tiene que revisar
y aplicar el esquema antes del primer despliegue.

| Fichero | Para qué |
| --- | --- |
| `postgres.sql` | Tablas del backend del frontal (`apps`, `scans`, `findings`, `finding_observations`, `finding_triage`). **Generado** desde `frontal/app/models.py`: no editar a mano |
| `generate_postgres_sql.py` | Regenera `postgres.sql` (`--check` comprueba que está al día; lo hace `tests/test_schema.py`) |
| `mongo-init.js` | Colecciones de MongoDB con validadores `$jsonSchema` e índices: ficheros de los runs (GridFS `strix_runs`) y `scans` del backend mínimo. Idempotente |

## PostgreSQL

```bash
psql "<URL del propietario de la BD>" -v ON_ERROR_STOP=1 -f frontal/schema/postgres.sql
# y al usuario de la aplicación, solo DML:
#   GRANT USAGE ON SCHEMA public TO <app>;
#   GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO <app>;
#   GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO <app>;
```

Va en una transacción: si falla (por ejemplo, porque las tablas ya existen) no deja nada a medias.
Con las tablas creadas, el backend arranca sin ejecutar DDL. Si cambian los modelos:
`python frontal/schema/generate_postgres_sql.py` y aplicar la diferencia (no hay migraciones automáticas).

Diferencia del triage (verdadero / falso positivo / dudoso), para una BD creada antes de 2026-10-23,
como propietario (el `GRANT ... ON ALL TABLES` anterior no cubre tablas nuevas, por eso se repite):

```sql
BEGIN;
ALTER TABLE findings ADD COLUMN triage VARCHAR(20);
CREATE TABLE finding_triage (
	id BIGSERIAL NOT NULL,
	finding_id BIGINT NOT NULL,
	decision VARCHAR(20) NOT NULL,
	justification TEXT,
	author VARCHAR(200),
	scan_id BIGINT,
	created_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL,
	PRIMARY KEY (id),
	FOREIGN KEY(finding_id) REFERENCES findings (id) ON DELETE CASCADE,
	FOREIGN KEY(scan_id) REFERENCES scans (id) ON DELETE SET NULL
);
CREATE INDEX ix_finding_triage_finding_id ON finding_triage (finding_id);
GRANT SELECT, INSERT, UPDATE, DELETE ON finding_triage TO <app>;
GRANT USAGE, SELECT ON SEQUENCE finding_triage_id_seq TO <app>;
COMMIT;
```

Si el backend se conecta como propietario de las tablas, lo hace solo al arrancar.

Probado en PostgreSQL 16:
- el esquema que deja `postgres.sql` es idéntico (`pg_dump -s`) al que crea la aplicación;
- aplicarlo dos veces, o sobre una BD donde ya existe una de las tablas, falla sin crear nada;
- el backend real (imagen `strix-frontal`) arranca y funciona con un usuario con exactamente los tres
  `GRANT` de arriba, al que se le deniega `CREATE TABLE`.

## MongoDB

```bash
mongosh "<MONGO_URI de un usuario con dbAdmin>" frontal/schema/mongo-init.js
MONGO_DB=strix MONGO_BUCKET=strix_runs SCHEMA_ACTION=warn mongosh "<MONGO_URI>" frontal/schema/mongo-init.js
```

`SCHEMA_ACTION=error` (por defecto) rechaza documentos que no cumplen el esquema; `warn` solo lo anota en el
log de Mongo. Las aplicaciones solo necesitan `readWrite`.

Probado en MongoDB 9.0.2, con un usuario solo `dbAdmin` para el script y uno solo `readWrite` para las apps:
- el script crea colecciones, validadores e índices, y repetirlo no rompe nada;
- en modo `error`, el orquestador sube runs (incluidos ficheros de más de un chunk) y los vuelve a subir, el
  frontal los descarga, y el backend mínimo completa un escaneo real de Strix y uno fallido;
- se rechazan documentos con estado inventado, sin `request`, con id ajeno o ficheros sin `metadata.run`;
- el usuario `readWrite` no puede quitar los validadores (`collMod` → Unauthorized);
- `SCHEMA_ACTION=warn` acepta lo inválido y se vuelve a `error` relanzando el script.
