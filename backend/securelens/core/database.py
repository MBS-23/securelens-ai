"""Database engine and session management (SQLAlchemy 2.0, synchronous).

PostgreSQL is the production database. SQLite is supported for development,
tests and single-user evaluation; foreign keys are switched on explicitly
because SQLite leaves them off by default.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager

from sqlalchemy import Engine, create_engine, event
from sqlalchemy.orm import Session, sessionmaker

from securelens.core.config import Settings, get_settings

_engine: Engine | None = None
_session_factory: sessionmaker[Session] | None = None


def build_engine(settings: Settings) -> Engine:
    if settings.is_sqlite:
        engine = create_engine(
            settings.database_url,
            connect_args={"check_same_thread": False, "timeout": 30},
            future=True,
        )

        @event.listens_for(engine, "connect")
        def _sqlite_pragmas(dbapi_connection, _record) -> None:  # pragma: no cover - driver hook
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.execute("PRAGMA busy_timeout=30000")
            if ":memory:" not in settings.database_url:
                cursor.execute("PRAGMA journal_mode=WAL")
            cursor.close()

        return engine
    return create_engine(settings.database_url, pool_pre_ping=True, pool_size=10, max_overflow=20, future=True)


def configure(settings: Settings | None = None) -> None:
    """(Re)initialise the global engine. Called at startup and by tests."""
    global _engine, _session_factory
    settings = settings or get_settings()
    settings.ensure_dirs()
    if _engine is not None:
        _engine.dispose()
    _engine = build_engine(settings)
    _session_factory = sessionmaker(bind=_engine, expire_on_commit=False, autoflush=False)


def get_engine() -> Engine:
    if _engine is None:
        configure()
    assert _engine is not None
    return _engine


def session_factory() -> sessionmaker[Session]:
    if _session_factory is None:
        configure()
    assert _session_factory is not None
    return _session_factory


def get_db() -> Iterator[Session]:
    """FastAPI dependency: one session per request, rolled back on error."""
    db = session_factory()()
    try:
        yield db
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


@contextmanager
def session_scope() -> Iterator[Session]:
    """Transactional scope for workers and scripts."""
    db = session_factory()()
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()
