"""API gateway. Deployed twice with different identities and network placement:

* ``GATEWAY_MODE=public`` (identity ``api-gateway-public``): internet-facing; widget chat,
  WhatsApp webhooks, signed security-ingest webhooks. Can reach SAMIIR-side services and the
  webhook routes of security-ingest only.
* ``GATEWAY_MODE=admin`` (identity ``api-gateway-admin``): staff console behind SSO/MFA
  (and, in production, a zero-trust access proxy); the only path to FATMA-side services.
"""
