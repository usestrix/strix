from __future__ import annotations

from collections.abc import Iterator

from sqlalchemy import create_engine, inspect
from sqlalchemy.orm import Session, sessionmaker

from frontal.app.config import get_settings
from frontal.app.models import Base


_settings = get_settings()

engine = create_engine(_settings.database_url, pool_pre_ping=True, future=True)
SessionLocal = sessionmaker(bind=engine, expire_on_commit=False, future=True)


def init_db() -> None:
    Base.metadata.create_all(engine)
    _add_missing_columns()


def _add_missing_columns() -> None:
    """Add nullable columns that models gained after their table was created.

    ``create_all`` never alters an existing table. This is not a migration tool:
    it only covers the additive, nullable columns this app introduces, so a
    database created by an earlier frontal keeps working.
    """
    inspector = inspect(engine)
    with engine.begin() as conn:
        for table in Base.metadata.sorted_tables:
            if not inspector.has_table(table.name):
                continue
            existing = {col["name"] for col in inspector.get_columns(table.name)}
            for column in table.columns:
                if column.name in existing or not column.nullable:
                    continue
                col_type = column.type.compile(dialect=engine.dialect)
                conn.exec_driver_sql(
                    f'ALTER TABLE "{table.name}" ADD COLUMN "{column.name}" {col_type}'
                )


def get_session() -> Iterator[Session]:
    with SessionLocal() as session:
        yield session
