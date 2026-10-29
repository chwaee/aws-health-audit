"""Text and JSON report renderers."""

from aws_health_audit.reporter.json import render_json
from aws_health_audit.reporter.text import render_text

__all__ = ["render_json", "render_text"]
