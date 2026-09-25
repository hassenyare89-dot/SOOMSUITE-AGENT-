"""Print the runtime requirements for an image: base dependencies plus selected extras.
Used by Dockerfiles so each image installs only what its service needs."""

from __future__ import annotations

import sys
import tomllib
from pathlib import Path

data = tomllib.loads(Path(sys.argv[1] if len(sys.argv) > 1 else "pyproject.toml").read_text())
project = data["project"]
lines = list(project["dependencies"])
for extra in (sys.argv[2].split(",") if len(sys.argv) > 2 and sys.argv[2] else []):
    lines += project["optional-dependencies"][extra]
print("\n".join(dict.fromkeys(lines)))
