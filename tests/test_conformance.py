import hashlib
import json

from frontier_shared.conformance import SUITES, bundled_lock_path, bundled_vectors_path, format_report, run_conformance


def test_bundled_vectors_are_fully_conformant():
    report = run_conformance()
    assert report["failed"] == 0, format_report(report)
    assert report["skipped"] == 0
    assert report["conformant"] is True
    assert report["passed"] >= 60


def test_every_suite_is_exercised():
    report = run_conformance()
    suites = {r["suite"] for r in report["results"]}
    assert suites == set(SUITES)


def test_a_vectors_file_missing_a_suite_is_not_conformant():
    vectors = json.load(open(bundled_vectors_path(), encoding="utf-8"))
    del vectors["rejections"]
    report = run_conformance(vectors)
    assert report["conformant"] is False
    assert any(r["suite"] == "rejections" and r["status"] == "failed" for r in report["results"])


def test_vendored_vectors_match_the_published_lock():
    text = open(bundled_vectors_path(), encoding="utf-8", newline="").read().replace("\r\n", "\n")
    lock = json.load(open(bundled_lock_path(), encoding="utf-8"))
    assert hashlib.sha256(text.encode("utf-8")).hexdigest() == lock["sha256"]
    assert json.loads(text)["vectors_version"] == lock["vectors_version"]
