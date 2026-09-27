import uuid

from platform_core.schemas.security import EventCategory
from security_ingest.normalizers import NormContext, aws_waf, cloudflare, normalize_all, proxy_log
from security_ingest.signatures import classify_request

CTX = NormContext(tenant_id=uuid.uuid4(), asset_id=None, source="test", pseudonym_key=b"k" * 32)


def test_signature_classifier():
    cats = {c for c, *_ in classify_request("/search", "q=%3Cscript%3Ealert(1)%3C/script%3E")}
    assert EventCategory.XSS in cats
    cats = {c for c, *_ in classify_request("/files", "p=../../../../etc/passwd")}
    assert EventCategory.PATH_TRAVERSAL in cats
    cats = {c for c, *_ in classify_request("/p", "id=1 UNION SELECT user,pass FROM users")}
    assert EventCategory.SQL_INJECTION in cats
    assert classify_request("/products", "page=2") == []


def test_cloudflare_record_redacts_query_secrets():
    ev = cloudflare({"RayID": "r1", "ClientIP": "198.51.100.1", "ClientRequestPath": "/login",
                     "ClientRequestQuery": "?token=abcdef123456&x=1", "Action": "block",
                     "Source": "firewallManaged", "Datetime": "2026-09-24T10:00:00Z",
                     "ClientCountry": "de"}, CTX)
    assert ev[0].country == "DE" and ev[0].category is EventCategory.WAF_BLOCK
    assert "abcdef123456" not in (ev[0].request_path or "")


def test_aws_waf_labels_to_category_and_headers_minimized():
    ev = aws_waf({"timestamp": 1758700000000, "action": "BLOCK",
                  "terminatingRuleId": "AWS-AWSManagedRulesSQLiRuleSet",
                  "httpRequest": {"clientIp": "203.0.113.5", "country": "US", "uri": "/api",
                                  "args": "", "httpMethod": "POST", "requestId": "abc",
                                  "headers": [{"name": "Cookie", "value": "session=secret"},
                                              {"name": "User-Agent", "value": "curl/8"}]},
                  "labels": [{"name": "awswaf:managed:aws:sql-database:SQLi_Body"}]}, CTX)
    assert ev[0].category is EventCategory.SQL_INJECTION
    assert "secret" not in ev[0].model_dump_json()


def test_dedupe_keys_are_stable_and_bad_records_counted():
    rec = {"remote_addr": "192.0.2.1", "request_uri": "/?id=1", "status": "200",
           "time_iso8601": "2026-09-24T10:00:00+00:00", "request_id": "abc"}
    a, b = proxy_log(rec, CTX), proxy_log(rec, CTX)
    assert a[0].dedupe_key == b[0].dedupe_key
    events, rejected = normalize_all("proxy", [rec, "not-a-dict", {"remote_addr": "999.1.1.1"}],
                                     CTX, 100)
    assert len(events) == 1 and rejected == 2
