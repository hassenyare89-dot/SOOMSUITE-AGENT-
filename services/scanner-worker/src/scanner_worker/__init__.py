"""Isolated scanner & malware-analysis workers.

These processes have no database credentials, no platform secrets and no inbound network
exposure. They receive work only from Temporal task queues and return normalized results."""
