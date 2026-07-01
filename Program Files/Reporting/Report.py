from __future__ import annotations

from Models import DetectionResult, IncidentCluster
from Timeline.Builder import build_timeline

def render_report(cluster: IncidentCluster, detections: list[DetectionResult], summary: dict) -> str:
    lines: list[str] = []

    lines.append(f"=== {cluster.incident_id} ===")
    lines.append(f"Cluster key: {cluster.key}")
    lines.append("")
    lines.append("Incident Summary")
    lines.append(summary["incident_summary"])
    lines.append("")
    lines.append("Timeline")
    for line in build_timeline(cluster.events):
        lines.append(f"- {line}")
    lines.append("")
    lines.append("Detection Findings")
    for det in detections:
        status = "TRIGGERED" if det.triggered else "not triggered"
        lines.append(f"- {det.name}: {status} (confidence={det.confidence:.2f})")
        if det.summary:
            lines.append(f"  {det.summary}")
        for detail in det.details:
            lines.append(f"  evidence: {detail}")
    lines.append("")
    lines.append("Interpretation")
    lines.append(summary["interpretation"])
    lines.append("")
    lines.append(f"Confidence: {summary['confidence']}")
    lines.append("")
    lines.append("Recommended Actions")
    for item in summary["recommendations"]:
        lines.append(f"- {item}")
    lines.append("")
    if summary["relevant_docs"]:
        lines.append("Relevant Documents")
        for title, excerpt in summary["relevant_docs"]:
            lines.append(f"- {title}: {excerpt}")

    return "\n".join(lines)
