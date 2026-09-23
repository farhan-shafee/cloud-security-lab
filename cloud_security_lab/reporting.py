"""Stable, portable evidence rendering. Reports contain no wall-clock values."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def _json(data: Any) -> str:
    return json.dumps(data, indent=2, sort_keys=True, ensure_ascii=True, allow_nan=False)


def _block(data: Any) -> str:
    # Fixture-controlled text cannot terminate a Markdown fence or emit raw HTML.
    safe = _json(data).replace("`", "\\u0060").replace("<", "\\u003c")
    return "```json\n" + safe + "\n```"


def render(data: dict[str, Any], format_name: str = "json") -> str:
    """Render complete JSON, detailed Markdown, or a concise terminal summary."""
    if format_name == "json":
        return _json(data) + "\n"
    if format_name == "text":
        lines = ["Synthetic cloud security evidence (offline fixtures)"]
        if "verified_closed" in data:
            lines.append(
                f"Verification: {data['verified_closed']} VERIFIED_CLOSED, "
                f"{data['open']} OPEN, {len(data['new_findings'])} new finding(s)"
            )
        elif "alerts" in data:
            lines.append(
                f"Events: {data['event_count']}; alerts: {len(data['alerts'])}; "
                f"correlations: {len(data['correlations'])}"
            )
        elif "controls_executed" in data:
            lines.append(
                f"Snapshot: {data['snapshot_id']}; controls: "
                f"{len(data['controls_executed'])}; findings: {len(data['findings'])}"
            )
        for item in data.get("findings", []) + data.get("alerts", []):
            identifier = item.get("control_id", item.get("detection_id", ""))
            lines.append(
                f"{identifier} | {item.get('severity', '')} | "
                f"{item.get('resource_id', '')} | {item.get('status', 'REVIEW')}"
            )
            if item.get("evidence"):
                lines.append("  Evidence: " + json.dumps(item["evidence"], sort_keys=True))
        for correlation in data.get("correlations", []):
            lines.append(
                f"{correlation['correlation_id']} | ESCALATE | "
                f"events: {', '.join(correlation['event_ids'])}"
            )
        return "\n".join(lines) + "\n"
    if format_name != "markdown":
        raise ValueError(f"Unknown report format: {format_name}")
    sections = [
        "# Synthetic cloud security evidence",
        "Generated from synthetic configuration/audit fixtures. "
        "No AWS services were contacted. PASS and closure apply only to modeled predicates.",
    ]
    collections = tuple(
        key
        for key in ("findings", "alerts", "correlations", "triage", "evaluations", "new_findings")
        if isinstance(data.get(key), list)
    )
    metadata = {key: value for key, value in data.items() if key not in collections}
    sections.extend(["## Assessment metadata", _block(metadata)])
    for key in collections:
        if key not in data:
            continue
        sections.append("## " + key.replace("_", " ").title())
        if not data[key]:
            sections.append("None.")
        for item in data[key]:
            sections.append(_block(item))
    return "\n\n".join(sections) + "\n"


def write_report(path: Path, data: dict[str, Any], format_name: str) -> None:
    """Write deterministic UTF-8 with LF newlines on Windows and Linux."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render(data, format_name), encoding="utf-8", newline="\n")
