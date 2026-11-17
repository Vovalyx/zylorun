"""Accuracy tests for the log & code analyzer against a ground-truth corpus.

A case passes only when the analyzer reports exactly the expected Critical and
Warning findings (right rule, severity and line) and the right overall status.
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(__file__))

from log_analyzer_corpus import CASES, FAKE_GITHUB_TOKEN, FAKE_DB_PASSWORD  # noqa: E402
from app.services.log_analyzer import analyze_text  # noqa: E402


def _matches(expected, finding):
    if finding["rule_id"] != expected["rule"] or finding["severity"] != expected["severity"]:
        return False
    if "line" in expected and finding["line"] != expected["line"]:
        return False
    if "count" in expected and finding["count"] != expected["count"]:
        return False
    text = finding["message"] + " " + finding.get("recommendation", "")
    return all(part in text for part in expected.get("contains", []))


def evaluate(case):
    result = analyze_text(case["text"], case.get("file_name"))
    findings = list(result["findings"])
    missing = []
    for expected in case["expect"]:
        hit = next((f for f in findings if _matches(expected, f)), None)
        if hit is None:
            missing.append(expected)
        else:
            findings.remove(hit)
    unexpected = [f for f in findings if f["severity"] in ("Critical", "Warning")]
    return result, missing, unexpected


@pytest.mark.parametrize("case", CASES, ids=[c["id"] for c in CASES])
def test_corpus_case(case):
    result, missing, unexpected = evaluate(case)
    assert not missing, f"missed findings: {missing}\nreported: {[f['message'] for f in result['findings']]}"
    assert not unexpected, f"false positives: {[(f['rule_id'], f['severity'], f['message']) for f in unexpected]}"
    assert result["status"] == case["expect_status"]


def test_secret_values_are_never_returned_in_clear_text():
    case = next(c for c in CASES if c["id"] == "vulnerable_python")
    result = analyze_text(case["text"], case["file_name"])
    blob = repr(result)
    assert FAKE_GITHUB_TOKEN not in blob
    assert FAKE_DB_PASSWORD not in blob


def test_zip_style_multi_file_input_keeps_files_and_line_numbers_apart():
    text = (
        "--- File: src/db.py ---\n"
        "import os\n"
        "def q(c, name):\n"
        "    c.execute(f\"SELECT * FROM t WHERE n = '{name}'\")\n"
        "--- File: logs/app.log ---\n"
        "2026-11-17 10:00:00 ERROR worker: job 7 failed\n"
        "--- File: package-lock.json ---\n"
        "{\"password\": \"Q9x-not-scanned-lockfile\"}\n"
    )
    result = analyze_text(text)
    located = {(f["file"], f["line"], f["rule_id"]) for f in result["findings"]}
    assert ("src/db.py", 3, "SEC-SQLI") in located
    assert ("logs/app.log", 1, "LOG-LEVEL-ERROR") in located
    assert not any(f["file"] == "package-lock.json" for f in result["findings"])
    assert result["summary"]["files_analyzed"] == 2
    assert result["summary"]["files_skipped"] == 1


def test_repeated_events_are_merged_with_a_count():
    text = "\n".join('10.0.0.1 - - [x] "GET /api/items HTTP/1.1" 502 0' for _ in range(40))
    result = analyze_text(text)
    assert len(result["findings"]) == 1
    assert result["findings"][0]["count"] == 40


def test_corpus_precision_and_recall_report():
    """Overall accuracy over the whole corpus; prints a short report with -s."""
    tp = fp = fn = 0
    for case in CASES:
        _, missing, unexpected = evaluate(case)
        expected = len(case["expect"])
        fn += len(missing)
        tp += expected - len(missing)
        fp += len(unexpected)
    precision = tp / (tp + fp) if tp + fp else 1.0
    recall = tp / (tp + fn) if tp + fn else 1.0
    print(f"\nanalyzer corpus: {tp} correct, {fp} false positives, {fn} missed; precision {precision:.3f}, recall {recall:.3f}")
    assert fp == 0 and fn == 0


def test_log_labelled_with_a_code_file_name_is_still_read_as_a_log():
    """Found by the browser end-to-end test: a crash log pasted while the page still held
    a sample's .js file name was read as code and reported as Pass."""
    case = next(c for c in CASES if c["id"] == "render_traceback")
    result = analyze_text(case["text"], "vulnerable_auth_handler.js")
    assert result["status"] == "Fail"
    assert any(f["rule_id"] == "LOG-PY-EXCEPTION" and f["line"] == 9 for f in result["findings"])
    assert result["summary"]["inputs"][0]["type"] == "log"


def test_real_code_with_a_code_file_name_stays_code():
    case = next(c for c in CASES if c["id"] == "ui_sample_vulnerable_js")
    result = analyze_text(case["text"], case["file_name"])
    assert result["summary"]["inputs"][0]["type"] == "code"


def test_root_cause_is_listed_before_its_after_effects():
    case = next(c for c in CASES if c["id"] == "render_traceback")
    first = analyze_text(case["text"])["findings"][0]
    assert first["rule_id"] == "LOG-PY-EXCEPTION"
    assert "secrets.py:340" in first["message"]
