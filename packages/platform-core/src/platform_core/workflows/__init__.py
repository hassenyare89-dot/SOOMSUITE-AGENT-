"""Temporal workflow definitions shared by starters and workers.

Workflows reference activities *by name* on dedicated task queues, so the public-facing
services never import scanner code and scanner workers never import database code:

* ``scanner``            — isolated scanner workers (no DB, no secrets, egress to targets only)
* ``malware-analysis``   — sandboxed malware workers (no network)
* ``scanner-controller`` — persistence activities with DB access
* ``security-ingest``    — persistence of malware verdicts
"""
