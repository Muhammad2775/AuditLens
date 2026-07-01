from __future__ import annotations

import argparse
import sys
from pathlib import Path

PROGRAM_FILES_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = PROGRAM_FILES_DIR.parent
if str(PROGRAM_FILES_DIR) not in sys.path:
    sys.path.insert(0, str(PROGRAM_FILES_DIR))

from Analysis.Explainer import summarize_incident
from Correlation.Engine import cluster_events
from Detection.Rules import run_all_detections
from Ingest.Loader import load_evidence
from Reporting.Report import render_report

def resolve_input_path(path: Path | None = None) -> Path:
    candidates = []
    if path is not None:
        candidates.append(path)

    candidates.extend(
        [
            PROGRAM_FILES_DIR / "Data",
            PROGRAM_FILES_DIR / "Data" / "Sample",
            PROJECT_ROOT / "Data",
            PROJECT_ROOT / "Data" / "Sample",
            Path("Data"),
            Path("Data") / "Sample",
        ]
    )

    for candidate in candidates:
        resolved = candidate if candidate.is_absolute() else (Path.cwd() / candidate).resolve()
        if resolved.exists():
            return resolved

    return (PROGRAM_FILES_DIR / "Data").resolve()

def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="AuditLens Security Event Correlation Engine")
    parser.add_argument(
        "--input",
        type=Path,
        default=resolve_input_path(),
        help="Path to a file or directory containing logs and markdown documents.",
    )
    return parser

def main() -> int:
    args = build_arg_parser().parse_args()
    store = load_evidence(args.input)

    if not store.events and not store.documents:
        print("No Evidence Found.")
        return 1

    clusters = cluster_events(store.events)

    if not clusters:
        print("No Incident Clusters Formed.")
        return 0

    for cluster in clusters:
        detections = run_all_detections(cluster.events)
        summary = summarize_incident(cluster, detections, store.documents)
        report = render_report(cluster, detections, summary)
        print(report)
        print("\n" + "=" * 80 + "\n")

    return 0

if __name__ == "__main__":
    raise SystemExit(main())
