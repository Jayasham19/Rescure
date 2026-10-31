"""
CalmStacks ReSecure Database Package
System: ReSecure (MVP v1.0)
Package: resecure.backend.src.db
"""

from .connection import (
    DEFAULT_BUSY_TIMEOUT_MS,
    DEFAULT_DB_FILENAME,
    DatabaseConnectionManager,
    get_connection_manager,
    get_db,
    get_default_db_path,
)
from .models import (
    ChunkModel,
    CorruptionEventModel,
    FileModel,
    FormatValidationModel,
    ManifestModel,
    RecoveryJobModel,
)
from .repository import (
    BaseRepository,
    ChunkRepository,
    CorruptionEventRepository,
    FileRepository,
    FormatValidationRepository,
    ManifestRepository,
    RecoveryJobRepository,
    ReSecureRepository,
)
from .schema import (
    EXPECTED_INDEXES,
    EXPECTED_TABLES,
    get_schema_sql,
    init_db,
    reset_db,
    verify_schema,
)

__all__ = [
    # Connection
    "DatabaseConnectionManager",
    "get_connection_manager",
    "get_db",
    "get_default_db_path",
    "DEFAULT_DB_FILENAME",
    "DEFAULT_BUSY_TIMEOUT_MS",
    # Schema & Migrations
    "init_db",
    "reset_db",
    "verify_schema",
    "get_schema_sql",
    "EXPECTED_TABLES",
    "EXPECTED_INDEXES",
    # Models
    "FileModel",
    "ManifestModel",
    "ChunkModel",
    "RecoveryJobModel",
    "CorruptionEventModel",
    "FormatValidationModel",
    # Repositories
    "BaseRepository",
    "FileRepository",
    "ManifestRepository",
    "ChunkRepository",
    "RecoveryJobRepository",
    "CorruptionEventRepository",
    "FormatValidationRepository",
    "ReSecureRepository",
]
