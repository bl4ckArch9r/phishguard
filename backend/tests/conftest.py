import os
import sys
import tempfile
from pathlib import Path

# Isolated database + path setup BEFORE the app is imported.
os.environ["PHISHGUARD_DB"] = str(Path(tempfile.mkdtemp()) / "test.db")
os.environ.pop("PHISHGUARD_ALLOW_PRIVATE", None)
os.environ["PHISHGUARD_BROWSER"] = "0"   # browser tests switch it on themselves
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
