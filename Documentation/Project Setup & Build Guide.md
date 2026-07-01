# Project Setup & Build Guide

## 1. Introduction
This guide details the complete environment configuration, build process, and execution steps for the **AuditLens** Proof-of-Concept (POC). By following these instructions, you will establish a stable, isolated workspace designed to parse security logs, execute deterministic detection rules, and generate AI-assisted incident summaries without deployment overhead.

# 2. Before You Begin
Ensure your system meets the baseline requirements before initializing the development environment.

## System Requirements
- **Python**
  - Version **3.9** or later
  - Installed and globally accessible

- **Workspace Context**
  - The **Program Files** directory **must** be opened as the workspace root inside your IDE.
  - This ensures Python correctly resolves internal imports such as:

```python
from Models import Event
```

### Build-System Note
Ensure your terminal environment allows activation of Python virtual environments.

Install the project in **editable mode** so source modifications are immediately reflected without rebuilding. Run the command from the repository root (no need to `cd` into `Program Files`).

- Python execution policies permit virtual environment activation.
- Your system `PATH` correctly resolves either `python` or `python3` to your installed Python interpreter rather than a Windows Store alias or other system redirect.

# 3. Required VS Code Extensions
To maximize development accuracy and leverage the project's internal architecture, install the following extensions.

| Extension | Purpose |
|-----------|---------|
| **Python (ms-python.python)** | Core Python language support |
| **Pylance (ms-python.vscode-pylance)** | Static type checking, IntelliSense, and improved navigation |

## Required Packages
AuditLens relies primarily on Python's standard library. However, modern Python packaging tools should be installed before building the project.

```bash
pip install --upgrade pip setuptools build
```

# 4. Cloning the Repository
Clone the repository and initialize an isolated Python virtual environment.

```bash
# Clone the repository
git clone https://github.com/Muhammad2775/AuditLens

# Navigate into the project
cd AuditLens

# Create a virtual environment
python -m venv venv

# Activate the environment (Windows)
venv\Scripts\activate
```

# 5. Building the Project
AuditLens utilizes a modern pyproject.toml configuration for its build system.
Ensure the `pyproject.toml` file exists in the repository root (project root). Modern Python build tools read configuration from this file.

Example minimal `pyproject.toml`:

```toml
[build-system]
requires = ["setuptools>=61.0"]
build-backend = "setuptools.build_meta"

[project]
name = "AuditLens"
version = "0.1.0"
requires-python = ">=3.14.5"
```
Install the project in **editable mode** so source modifications are immediately reflected without rebuilding. Run the command from the repository root (no need to `cd` into `Program Files`).

```powershell
# From repository root
python -m pip install -e .
```

If you prefer an explicit step sequence, the full minimal flow is:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip setuptools build
python -m pip install -e .
```

# 6. Running the Project
Once the virtual environment has been activated and the project installed, the application can be executed directly from the terminal.

## Run Using Default Sample Dataset

The following command processes the contents of the `Data/Sample` directory (run from the repository root):

```powershell
python "Program Files/Auditlens.py"
```

## Run Against a Custom Dataset
Specify an individual file or directory using the `--input` argument.

```powershell
python "Program Files/Auditlens.py" --input "../Data/Raw/custom_logs.csv"
```

## Execute the Unit Test Suite
Run the deterministic detection engine tests.

```bash
python -m unittest TestRules.py
```

# 7. Common Errors
## Repository Cloning Issues

### Error

```text
fatal: Authentication failed...
```

or

```text
- Python execution policies permit virtual environment activation.
```

### Solution
Verify that:

- Your Git authentication credentials are valid.
- SSH keys or Personal Access Tokens (PATs) are correctly configured.
- Network connectivity to the remote repository is available.

## Project Build Issues

### Error
```text
ERROR: File "setup.py" or "setup.cfg" not found.
```

### Solution
Update your build tools.

```bash
pip install --upgrade pip setuptools build
```

AuditLens uses the modern `pyproject.toml` build standard, which requires recent versions of **pip** and **setuptools (>=61.0)**.

## Environment Issues

### Error
```text
ModuleNotFoundError: No module named 'Models'
```

### Solution
This typically occurs when the project is executed outside the **Program Files** directory.

Ensure:

- Your current terminal directory is:

```text
Program Files
```

- Your IDE workspace root is also set to **Program Files** rather than the parent **AuditLens** directory.

## Package Installation Issues

### Error (Windows)
```text
Execution of scripts is disabled on this system.
```

### Solution
PowerShell is blocking virtual environment activation.

Execute:

```powershell
Set-ExecutionPolicy Unrestricted -Scope CurrentUser
```

Then reactivate the virtual environment.

## Project Execution Issues

### Error
```text
No Evidence Found
```

### Solution
The ingestion engine could not locate supported input files.

Verify that:

- Your dataset contains valid files.
- Supported file types include:
  - `.csv`
  - `.txt`
  - `.md`
  - `.json`
- Files are located in:

```text
Data/Sample
```

or within the directory explicitly provided using:

```bash
--input
```

# 8. Conclusion
Following this guide produces a fully functional, offline-capable development environment engineered to ingest heterogeneous security logs, evaluate them using deterministic detection rules, and reconstruct chronological incident timelines. The project intentionally isolates its analytical core from heavy external dependencies, allowing AuditLens to demonstrate rapid, explainable, evidence-based security event correlation while remaining lightweight, portable, and easily auditable.