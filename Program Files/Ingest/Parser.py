from __future__ import annotations

import csv
import re
from pathlib import Path

from Models import Document

SYSTEM_LOG_RE = re.compile(
    r'^(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) '
    r'host=(?P<host>\S+) '
    r'process=(?P<process>\S+) '
    r'parent=(?P<parent>\S+) '
    r'action=(?P<action>\S+) '
    r'severity=(?P<severity>\S+) '
    r'message="(?P<message>.*)"$'
)

APPLICATION_LOG_RE = re.compile(
    r'^\[(?P<timestamp>[^\]]+)\] '
    r'app=(?P<app>\S+) '
    r'host=(?P<host>\S+) '
    r'user=(?P<user>\S+) '
    r'event=(?P<event>\S+) '
    r'result=(?P<result>\S+) '
    r'ip=(?P<ip>\S+) '
    r'msg="(?P<message>.*)"$'
)

def parse_csv_audit_log(path: Path) -> list[dict]:
    records: list[dict] = []
    with path.open("r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            row["source_file"] = path.name
            row["source_type"] = "csv"
            records.append(row)
    return records

def parse_text_log(path: Path) -> list[dict]:
    records: list[dict] = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue

            system_match = SYSTEM_LOG_RE.match(line)
            if system_match:
                data = system_match.groupdict()
                data["source_file"] = path.name
                data["source_type"] = "txt_system"
                data["record_kind"] = "event"
                data["process_name"] = data.pop("process")
                data["parent_process_name"] = data.pop("parent")
                records.append(data)
                continue

            app_match = APPLICATION_LOG_RE.match(line)
            if app_match:
                data = app_match.groupdict()
                data["source_file"] = path.name
                data["source_type"] = "txt_application"
                data["record_kind"] = "event"
                data["action"] = data.pop("event")
                data["outcome"] = data.pop("result")
                records.append(data)
                continue

            records.append(
                {
                    "timestamp": "",
                    "host": "",
                    "user": "",
                    "ip": "",
                    "action": "raw_log",
                    "severity": "low",
                    "message": line,
                    "source_file": path.name,
                    "source_type": "txt_raw",
                    "record_kind": "event",
                }
            )

    return records

def parse_markdown_document(path: Path) -> Document:
    content = path.read_text(encoding="utf-8")
    title = path.stem.replace("-", " ").replace("_", " ").title()

    for line in content.splitlines():
        stripped = line.strip()
        if stripped.startswith("#"):
            title = stripped.lstrip("#").strip()
            break

    return Document(path=path, title=title, content=content)

def parse_file(path: Path):
    suffix = path.suffix.lower()
    if suffix == ".csv":
        return parse_csv_audit_log(path)
    if suffix == ".txt":
        return parse_text_log(path)
    if suffix == ".md":
        return parse_markdown_document(path)
    return []
