"""Write the API's OpenAPI schema to a file (offline: /openapi.json needs the session token)."""

import json
import sys
from pathlib import Path

from verdikt.api.app import create_app

SCHEMA_ONLY_TOKEN = "schema-only"  # noqa: S105

app = create_app(port=8765, token=SCHEMA_ONLY_TOKEN)
Path(sys.argv[1]).write_text(json.dumps(app.openapi()), encoding="utf-8")
