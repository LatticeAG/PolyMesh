"""Run the installed PolyMesh command-line interface with ``python -m``."""

from .cli import _entrypoint


if __name__ == "__main__":  # pragma: no cover - exercised by packaging use
    _entrypoint()
