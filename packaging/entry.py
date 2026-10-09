"""PyInstaller entry point (the package itself uses relative imports)."""
from pcaptriage.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
