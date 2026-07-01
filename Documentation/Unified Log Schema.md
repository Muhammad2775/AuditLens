# Unified Log Schema
AuditLens is built on an **Evidence-First** architecture. To correlate activities across fragmented, heterogeneous data sources (CSV, TXT, JSON), the ingestion pipeline parses and normalizes every raw log into a single, unified `Event` schema. 

This standardization ensures the correlation engine (`Engine.py`) and detection rules (`Rules.py`) can operate deterministically, regardless of the originating system's native log format.

## Core Event Schema
The following table defines the standard fields for every normalized event object in memory.

| Field | Type | Description | Allowable / Inferred Values |
| :--- | :--- | :--- | :--- |
| `timestamp` | `datetime` | The precise time the event occurred, always normalized to UTC. | ISO-8601 compliant strings. |
| `user` | `string` | The user account or identity performing the action. | Standardized via whitespace stripping. |
| `ip_address` | `string` | The source or destination IP address associated with the event. | IPv4 / IPv6 addresses. |
| `host` | `string` | The target or origin machine hostname. | |
| `action` | `string` | The standardized verb or action executed (e.g., `failed_login`, `start`). | |
| `message` | `string` | The raw or descriptive textual payload of the event. | |
| `outcome` | `string` | The definitive result of the action. | `success`, `failure`, `error`, etc. |
| `source_file` | `string` | The originating file name where this event was found. | e.g., `application.log`, `audit.csv`. |
| `event_category` | `string` | The high-level classification of the event. If missing, it is inferred by the normalizer. | `authentication`, `privilege`, `process_execution`, `resource_access`, `policy`, `system_activity`. |
| `process_name` | `string` | *(Optional)* The name of the binary or executable involved. | e.g., `cmd.exe`, `powershell.exe`. |
| `parent_process_name` | `string` | *(Optional)* The parent process that spawned the executable. | e.g., `winword.exe`. |
| `source_type` | `string` | The format classification assigned by the parser. | `csv`, `txt_system`, `txt_application`, `event`. |
| `severity` | `string` | The impact level of the event. Defaults to `low` if unrecognized. | `low`, `medium`, `high`, `critical`. |
| `session_id` | `string` | *(Optional)* A unique identifier for a specific execution or login session. | |
| `raw` | `dict` | A dictionary containing the unmodified, original key-value pairs of the parsed log line. | Retained for strict evidence preservation. |

## Normalization & Inference Logic
The `Normalizer.py` module applies specific business logic to ensure missing or messy log data conforms to the schema:

### 1. Timestamp Normalization
All timestamps are parsed and explicitly cast to **UTC timezone-aware** `datetime` objects to ensure precise correlation windows across disparate geographic sources.

### 2. Implicit Category Inference
If a log source does not explicitly provide an `event_category`, the system infers it by analyzing the `action`, `message`, and `process_name` fields:
* **`authentication`**: Triggered by keywords like "login", "password".
* **`privilege`**: Triggered by keywords like "group_change", "sudo", "administrators".
* **`process_execution`**: Triggered by keywords like "cmd.exe", "powershell", "process".
* **`resource_access`**: Triggered by keywords like "file_access", "sensitive", "audit archive".

### 3. Severity Standardization
Any severity value outside the recognized matrix is automatically downgraded to `low` to prevent uncalibrated noise from artificially inflating incident confidence scores.

## Example Normalized Record (JSON Representation)
```json
{
  "timestamp": "2026-05-14T08:51:18Z",
  "user": "user1",
  "ip_address": "10.0.0.1",
  "host": "ws-014",
  "action": "start",
  "message": "Script process launched",
  "outcome": "success",
  "source_file": "sysmon-alerts.txt",
  "event_category": "process_execution",
  "process_name": "powershell.exe",
  "parent_process_name": "cmd.exe",
  "source_type": "txt_system",
  "severity": "medium",
  "session_id": "sess-88912",
  "raw": {
    "time": "2026-05-14 08:51:18",
    "host": "ws-014",
    "process": "powershell.exe",
    "parent": "cmd.exe",
    "action": "start",
    "severity": "medium",
    "message": "Script process launched"
  }
}