from scanner_worker.malware import detect_mime, inspect_zip, verdict_for
from scanner_worker.parsers import parse_nuclei, parse_zap
from scanner_worker.profiles import DEFAULT_EXCLUDED_TAGS, PROFILES, nuclei_args, zap_plan


def test_every_profile_excludes_destructive_templates():
    for profile in PROFILES.values():
        args = nuclei_args(profile, "https://example.com/", "/tmp/o")
        excluded = args[args.index("-etags") + 1].split(",")
        for tag in ("dos", "fuzz", "bruteforce", "default-login", "intrusive", "rce"):
            assert tag in excluded
        assert "-ni" in args  # no out-of-band interaction
        assert not set(profile.nuclei_tags) & set(DEFAULT_EXCLUDED_TAGS)


def test_zap_plan_is_passive_only():
    plan = zap_plan(PROFILES["safe-standard"], "https://example.com/", "/tmp")
    job_types = [j["type"] for j in plan["jobs"]]
    assert "activeScan" not in job_types and "passiveScan-wait" in job_types


def test_parsers_normalize_and_fingerprint():
    line = ('{"template-id":"missing-hsts","info":{"name":"HSTS missing","severity":"low",'
            '"tags":["misconfig","headers"]},"matched-at":"https://example.com/?token=abc"}')
    f = parse_nuclei(line, "example.com")[0]
    assert f["category"] == "misconfiguration" and "abc" not in f["url"]
    z = parse_zap({"site": [{"alerts": [{"pluginid": "10038", "alert": "CSP not set",
                                          "riskcode": "2", "cweid": "693", "desc": "<p>x</p>",
                                          "instances": [{"uri": "https://example.com/"}]}]}]},
                  "example.com")[0]
    assert z["severity"] == "medium" and z["cwe"] == "CWE-693" and z["description"] == "x"


def test_malware_static_analysis_helpers():
    assert detect_mime(b"MZ\x90\x00") == "application/x-dosexec"
    assert detect_mime(b"%PDF-1.7") == "application/pdf"
    assert verdict_for("clean", [], {}, "application/x-dosexec", "application/pdf") == "suspicious"
    assert verdict_for("infected", [], {}, "text/plain", None) == "malicious"


def test_zip_bomb_and_executables_detected_without_extraction():
    import io
    import zipfile

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("big.txt", b"\0" * (20 * 1024 * 1024))
        z.writestr("run.exe", b"MZ")
    info = inspect_zip(buf.getvalue())
    assert info["bomb_suspected"] is True and "run.exe" in info["executables"]
