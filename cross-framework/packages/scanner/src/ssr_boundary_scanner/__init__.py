"""ssr-boundary-scanner — detect sensitive DB fields in SSR hydration payloads."""

from .scanner import scan_url
from .walker import Finding, TargetResult

__all__ = ["scan_url", "Finding", "TargetResult"]
__version__ = "0.1.0"
