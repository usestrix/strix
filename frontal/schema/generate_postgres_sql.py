"""Genera frontal/schema/postgres.sql a partir de los modelos (frontal/app/models.py).

El backend crea estas tablas solo al arrancar (init_db) si su usuario puede hacer
CREATE TABLE. Este DDL es para cuando no puede: un DBA lo ejecuta antes del primer
despliegue y el backend arranca con un usuario de solo lectura/escritura.

    uv run python frontal/schema/generate_postgres_sql.py          # reescribe postgres.sql
    uv run python frontal/schema/generate_postgres_sql.py --check  # falla si está desactualizado

tests/test_schema.py ejecuta el --check, así que un cambio en los modelos sin
regenerar este fichero se detecta en los tests.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
OUT = Path(__file__).with_name("postgres.sql")

HEADER = """\
-- Esquema PostgreSQL del backend del frontal de Strix.
-- GENERADO desde frontal/app/models.py con frontal/schema/generate_postgres_sql.py:
-- no editar a mano.
--
-- El backend crea estas tablas solo al arrancar si su usuario tiene permiso de CREATE.
-- Si no lo tiene, ejecutar este fichero UNA vez, como propietario de la base de datos:
--
--   psql "<URL del propietario>" -v ON_ERROR_STOP=1 -f postgres.sql
--
-- Va en una transacción: si algo falla (p. ej. las tablas ya existen) no cambia nada.
-- Después, conceder al usuario de la aplicación solo DML:
--
--   GRANT USAGE ON SCHEMA public TO <usuario_app>;
--   GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO <usuario_app>;
--   GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO <usuario_app>;
--
-- Con las tablas ya creadas, el arranque no ejecuta ningún DDL.

BEGIN;

"""


def render() -> str:
    # models.py no necesita conexión, pero config.py lee el entorno al importarse.
    os.environ.setdefault("FRONTAL_DATABASE_URL", "postgresql+psycopg://x:x@localhost/x")
    sys.path.insert(0, str(ROOT))
    from sqlalchemy.dialects import postgresql  # noqa: PLC0415
    from sqlalchemy.schema import CreateIndex, CreateTable  # noqa: PLC0415

    from frontal.app.models import Base  # noqa: PLC0415

    dialect = postgresql.dialect()
    parts = [HEADER]
    for table in Base.metadata.sorted_tables:
        ddl = str(CreateTable(table).compile(dialect=dialect)).strip()
        parts.append(f"{ddl};\n\n")
        parts.extend(
            f"{str(CreateIndex(index).compile(dialect=dialect)).strip()};\n"
            for index in sorted(table.indexes, key=lambda i: i.name or "")
        )
        if table.indexes:
            parts.append("\n")
    parts.append("COMMIT;\n")
    sql = "".join(parts)
    # SQLAlchemy deja un espacio tras cada coma de fin de línea.
    return "\n".join(line.rstrip() for line in sql.rstrip().splitlines()) + "\n"


def main() -> int:
    sql = render()
    if "--check" in sys.argv:
        current = OUT.read_text(encoding="utf-8") if OUT.exists() else ""
        if current != sql:
            print(f"{OUT} está desactualizado: regenerar con {Path(__file__).name}")
            return 1
        print(f"{OUT} al día")
        return 0
    OUT.write_text(sql, encoding="utf-8")
    print(f"escrito {OUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
