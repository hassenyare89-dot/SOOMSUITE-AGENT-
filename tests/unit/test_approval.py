from app.services.approvals import approval_matches, payload_hash


def test_parameter_change_invalidates_approval():
    approved = {"action": "block_ip", "ip": "203.0.113.9", "ttl": 300}
    digest = payload_hash(approved)
    assert approval_matches(approved, digest)
    assert not approval_matches(approved | {"ttl": 3600}, digest)
