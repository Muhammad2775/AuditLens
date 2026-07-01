from __future__ import annotations

import json
from pathlib import Path

from Models import Event, Document, EvidenceStore
from Utilities.time_utils import parse_timestamp
from Utilities.text_utils import normalize_whitespace
from Ingest.Parser import parse_file
from Ingest.Normalizer import normalize_event as normalize_record


def resolve_input_path(input_path: Path | str | None) -> Path | None:
    if input_path is None:
        return None

    path = Path(input_path).expanduser()
    if not path.is_absolute():
        path = (Path.cwd() / path).resolve()

    if path.exists():
        return path

    candidates = [
        path,
        path.parent / "Data",
        path.parent / "Data" / "Sample",
        path.parent.parent / "Data",
        path.parent.parent / "Data" / "Sample",
    ]

    for candidate in candidates:
        if candidate.exists():
            return candidate

    return path


def load_evidence(input_path: Path) -> EvidenceStore:
    #Finds all logs and docs inside input path and loads them into an EvidenceStore.
    store = EvidenceStore()
    resolved_path = resolve_input_path(input_path)
    if resolved_path is None:
        return store

    if resolved_path.is_file():
        paths = [resolved_path]
    elif resolved_path.is_dir():
        paths = sorted(resolved_path.rglob("*"))
    else:
        paths = []

    for p in paths:
        if not p.is_file():
            continue

        suffix = p.suffix.lower()

        try:
            parsed = parse_file(p)
        except Exception:
            parsed = []

        if parsed is None:
            continue

        # Markdown Document
        if suffix == ".md":
            if isinstance(parsed, list):
                for item in parsed:
                    if isinstance(item, dict):
                        try:
                            store.events.append(normalize_record(item, str(p)))
                        except Exception:
                            continue
            else:
                try:
                    store.documents.append(parsed)
                except Exception:
                    continue

        # CSV or TXT parsed into list of dicts
        elif suffix in {".csv", ".txt", ".log", ".json"}:
            if isinstance(parsed, list):
                for row in parsed:
                    try:
                        store.events.append(normalize_record(row, str(p)))
                    except Exception:
                        continue
            else:
                try:
                    content = p.read_text(encoding="utf-8", errors="ignore")
                    for line in content.splitlines():
                        if not line.strip():
                            continue
                        try:
                            row = json.loads(line)
                            store.events.append(normalize_record(row, str(p)))
                        except Exception:
                            continue
                except Exception:
                    continue

    return store
