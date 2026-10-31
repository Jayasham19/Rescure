"""
CalmStacks ReSecure Core Engine Main Entrypoint
System: ReSecure (MVP v1.0)
Module: resecure.backend.src.main
"""

import uvicorn
from resecure.backend.src.api.app import app


def main() -> None:
    uvicorn.run("resecure.backend.src.api.app:app", host="127.0.0.1", port=8000, reload=False)


if __name__ == "__main__":
    main()
