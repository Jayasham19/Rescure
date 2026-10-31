# ReSecure — Core Product Package

This directory contains the standalone source code, engines, API server, client interface, and container definitions for **ReSecure**.

## Package Structure

- **`backend/`**: FastAPI REST API server, cryptographic hashing engine, Reed–Solomon $GF(2^8)$ codec, format validators (Text, CSV, JSON, PNG, JPEG), and heuristic repair engine.
- **`frontend/`**: React 18, TypeScript, Vite, and Tailwind CSS cybersecurity dashboard with 64KB interactive chunk visualizer grid.
- **`ai/`**: Diagnostic ML corruption pattern classifier and format detector for headerless files.
- **`evals/`**: Evaluation benchmark harness comparing deterministic Reed-Solomon vs AI/heuristic recovery.
- **`database/`**: SQLite relational schema DDL (`resecure_schema.sql`) and deterministic seed fixtures.
- **`contracts/`**: Frozen OpenAPI 3.1 YAML, SQLite DDL, and TypeScript contract types.
- **`docs/`**: PRD, system architecture, ADRs, and verification reports.
- **`tests/`**: Acceptance and integration test suites.
- **`Dockerfile.backend`**: Multi-stage unprivileged Python 3.13 container.
- **`Dockerfile.frontend`**: Multi-stage unprivileged Nginx container with security headers.
- **`docker-compose.yml`**: Compose orchestration for running backend and frontend together.

## Quickstart

```powershell
# Automated setup
powershell -File ..\scripts\setup-resecure.ps1

# Run backend & frontend
powershell -File ..\scripts\run-resecure.ps1

# Or with Docker
docker compose up --build -d
```
