from frontier_shared.conformance import format_report, run_conformance


def test_bundled_vectors_are_fully_conformant():
    report = run_conformance()
    assert report["failed"] == 0, format_report(report)
    assert report["skipped"] == 0
    assert report["conformant"] is True
    assert report["passed"] >= 20


def test_every_suite_is_exercised():
    report = run_conformance()
    suites = {r["suite"] for r in report["results"]}
    assert suites == {"canonical_json", "base58btc", "did_key", "ed25519", "envelope", "receipt"}
