# AuditLens
AuditLens is a **Proof-of-Concept (POC)** security event correlation and investigation platform designed to help security analysts process fragmented logs, audit records, and operational documents. By combining deterministic security logic with AI-assisted reasoning, the system efficiently correlates suspicious activities across users, hosts, sessions, and timestamps to generate structured incident timelines and investigation summaries.

# Project Scope
This project operates as a lightweight, offline-friendly proof of concept targeting small-scale, synthetic datasets. It validates the integration of heterogeneous log parsing (CSV, TXT, Markdown) with a deterministic correlation engine and AI-assisted interpretation, serving as a foundational prototype for a larger-scale incident response architecture.

## Quickstart
Run these commands from the repository root to create a virtual environment, install the project in editable mode, and execute the sample dataset (Windows PowerShell shown):

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip setuptools build
python -m pip install -e .
python "Program Files/Auditlens.py"
```

On POSIX shells the activation step differs:

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip setuptools build
python -m pip install -e .
python "Program Files/Auditlens.py"
```

# Core Objectives
## Augment Investigation Workflows
Reduce the manual overhead analysts face when tracing events across multiple systems and log formats.

## Maintain Deterministic Integrity
Rely strictly on evidence-based logic for detection rather than opaque AI inferences.

## Demonstrate AI as an Assistant
Utilize AI solely to summarize findings, interpret correlated evidence, and suggest operational playbooks.

## Establish Explainability
Ensure every triggered detection includes the raw supporting evidence, a generated timeline, and a clear rationale.

# Architecture & Design Philosophy
The system is built on a highly modular pipeline that adheres to six core principles:

- **Evidence First**  
  All conclusions must be grounded in actual log evidence and correlated events.

- **Deterministic Security Logic**  
  Suspicious activity detection relies on deterministic rules rather than probabilistic guesses.

- **AI as an Assistant**  
  AI interprets and summarizes but does not replace the evidence-based reasoning engine.

- **Security Context Awareness**  
  Analysis natively considers user behavior, privilege levels, host activity, and temporal relationships.

- **Modular Design**  
  Each subsystem (Ingestion, Correlation, Detection, Reporting) is completely isolated and independently testable.

- **Explainability**  
  Confidence scores and rule triggers are explicitly mapped back to the raw source data.

# Pipeline Processing
1. **Load Data**
   - Extract heterogeneous logs and documents from the `Data/Raw` and `Data/Sample` directories.

2. **Ingestion & Normalization**
   - Parse supported file formats and normalize all records into a unified UTC-timestamped schema.

3. **Correlation**
   - Group related events dynamically using user, host, IP address, session identifiers, and a configurable 15-minute correlation window.

4. **Detection Engine**
   - Execute predefined deterministic security detection rules against correlated event clusters.

5. **Timeline & AI Generation**
   - Reconstruct a chronological sequence of events and generate an analyst-focused investigation summary.

# Data Model
All ingested logs are normalized into a **Unified Event Structure**, ensuring the correlation engine operates on standardized entities.

```json
{
  "timestamp": "UTC normalized datetime",
  "host": "Target or origin machine",
  "user": "Account performing the action",
  "ip_address": "Source or destination IP",
  "action": "Standardized event action",
  "severity": "low | medium | high | critical",
  "event_category": "authentication | privilege | process_execution | resource_access",
  "message": "Raw or descriptive event text",
  "source_file": "Originating log file",
  "session_id": "Optional execution session",
  "outcome": "success | failure"
}
```

# Features

## Multi-Format Ingestion
Seamlessly parses:

- CSV audit logs
- Structured TXT system/application logs
- Markdown policy and documentation files

## Dynamic Event Correlation
Uses flexible composite correlation keys such as:

- `user | ip | host`
- `host | process`
- Session identifiers
- Time-window relationships

to build isolated incident clusters.

## Predefined Detection Rules
- **Brute-Force Authentication**
  - Threshold-based failed authentication attempts followed by a successful login.

- **Privilege Escalation**
  - Administrative group modifications and elevated privilege assignments.

- **Suspicious Process Chaining**
  - Detects suspicious execution chains such as:

  ```
  winword.exe
      ↓
    cmd.exe
      ↓
  powershell.exe
  ```

- **Restricted Resource Access**
  - Detects interaction with confidential or restricted files.

## Automated Timeline Reconstruction
Generates human-readable chronological investigation timelines from multiple heterogeneous data sources.

## AI-Assisted Context Extraction
Automatically extracts and scores relevant excerpts from Markdown security playbooks and policy documents to enrich the final investigation report.

# Repository Structure
```text
AuditLens/
├── Data/
│   └── incident_notes.md
│   └── application_log.txt
│   └── system_log.txt
│   └── audit_log.csv
│
├── Documentation/
│   └──Project Setup & Build Guide.md
│   └──README.md
│   └──Technical Project Guide.md
│   └──Unified Log Schema.md
│
├──Test/
│  └──test_imports.py
│
└── Program Files/
    ├── Analysis/
    │   └── Explainer.py
    │
    ├── Correlation/
    │   └── Engine.py
    │
    ├── Detection/
    │   └── Rules.py
    │
    ├── Ingest/
    │   ├── Loader.py
    │   ├── Normalizer.py
    │   └── Parser.py
    │
    ├── Reporting/
    │   └── Report.py
    │
    ├── Timeline/
    │   └── Builder.py
    │
    ├── Utilities/
    │   ├── text_utils.py
    │   └── time_utils.py
    │
    ├── Models.py
    ├── Configuration.py
    ├── Auditlens.py
    ├── TestRules.py
    └── ImportVerification.py
```

# Summary
AuditLens demonstrates how robust, deterministic security engineering can be combined with AI-assisted summarization to significantly reduce incident investigation time. By normalizing fragmented security data, correlating suspicious activity through explainable deterministic logic, and generating evidence-backed timelines, the platform provides analysts with a clear and defensible narrative of complex security incidents while preserving transparency throughout the investigation process.

# Disclaimer
This project is designed strictly for learning purposes and must not be considered a competitor to a professional SIEM etc.

# Contact
For questions, feedback, feature requests, or technical discussions, please use the repository's **Discussions** section.

For urgent matters, contact the repository owner at:  
**muhammad.moazzam2775@gmail.com**