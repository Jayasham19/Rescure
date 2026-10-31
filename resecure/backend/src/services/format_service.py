"""
CalmStacks ReSecure Application Tier - Format Service
System: ReSecure (MVP v1.0)
Module: resecure.backend.src.services.format_service
"""

from __future__ import annotations

import datetime
import json
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from ..core.format_validators import validate_format
from ..core.reedsolomon import NonDestructiveViolationError
from ..core.repair_engine import repair_file_format
from ..db.connection import get_connection_manager
from ..db.models import FormatValidationModel
from ..db.repository import ReSecureRepository


class FormatService:
    """Orchestrates multi-format deep structural validation and heuristic structural repair."""

    def __init__(self, repo: Optional[ReSecureRepository] = None) -> None:
        self.repo = repo or ReSecureRepository(get_connection_manager())

    def validate(
        self,
        source_path: Union[str, Path],
        format_name: str = "AUTO",
    ) -> Dict[str, Any]:
        """
        Executes deep structural validation on target file and persists findings.
        """
        src = Path(source_path).resolve()
        if not src.is_file():
            raise FileNotFoundError(f"Target file not found: {source_path}")

        result = validate_format(src, format_name=format_name)

        # Count errors & warnings
        findings = result.get("findings", [])
        error_count = sum(1 for f in findings if f.get("severity") == "ERROR")
        warning_count = sum(1 for f in findings if f.get("severity") == "WARNING")

        validation_id = str(uuid.uuid4())
        now_iso = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")

        validation_model = FormatValidationModel(
            validation_id=validation_id,
            filename=src.name,
            detected_format=result["format"],
            is_valid=1 if result["is_valid"] else 0,
            error_count=error_count,
            warning_count=warning_count,
            details_json=json.dumps({"findings": findings, "metrics": result.get("metrics", {})}),
            format_verdict=result["verdict"],
            created_at=now_iso,
        )
        self.repo.format_validations.create(validation_model)

        return result

    def repair(
        self,
        source_path: Union[str, Path],
        output_path: Union[str, Path],
        format_name: str = "AUTO",
    ) -> Dict[str, Any]:
        """
        Executes best-effort heuristic structural repair with explicit disclosure logging.
        """
        src = Path(source_path).resolve()
        out = Path(output_path).resolve()

        if src == out:
            raise NonDestructiveViolationError(
                f"Non-Destructive Invariant Violation: output_path '{out}' must not equal source_path '{src}'"
            )

        if not src.is_file():
            raise FileNotFoundError(f"Source file not found: {source_path}")

        result = repair_file_format(
            source_path=src,
            output_path=out,
            format_name=format_name,
        )

        validation_id = str(uuid.uuid4())
        now_iso = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")

        validation_model = FormatValidationModel(
            validation_id=validation_id,
            filename=out.name,
            detected_format=result["format"],
            is_valid=1,
            error_count=0,
            warning_count=result["mutations_count"],
            details_json=json.dumps({"repair_log": result["repair_log"]}),
            format_verdict="STRUCTURALLY_SALVAGED",
            repair_log_json=json.dumps(result["repair_log"]),
            created_at=now_iso,
        )
        self.repo.format_validations.create(validation_model)

        return result
