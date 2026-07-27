"""Agent Wormhole: stop self-replicating prompt payloads spreading between agents."""

# Read from installed distribution metadata rather than hardcoding, so the
# version can never disagree with what pip actually installed. importlib
# .metadata is stdlib from 3.8; a source checkout that was never installed
# falls back to "0+unknown" rather than failing to import.
try:  # pragma: no cover - trivial import guard
    from importlib.metadata import PackageNotFoundError, version as _version
    try:
        __version__ = _version("wormhole-guard")
    except PackageNotFoundError:
        __version__ = "0+unknown"
except ImportError:  # pragma: no cover - Python < 3.8
    __version__ = "0+unknown"

__all__ = ["__version__"]
