"""Allow running the orchestrator as a module.

Usage:
    python -m scripts.orchestrator --alert alert.json
    python -m scripts.orchestrator --alert alert.json --playbook playbooks/identity-compromise.yaml
"""
from .orchestrator import main

raise SystemExit(main())
