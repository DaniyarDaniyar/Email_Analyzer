from apps.detector.services.analysis import compute_scores


def test_compute_scores_ai_only():
    """When no reputation indicators or headers are present, final score should
    equal the AI confidence (AI is the dominant signal)."""
    parsed = {}
    reputation = {"urls": {}, "domains": {}, "ips": {}}
    # with no reputation data the score should follow whatever the AI thinks is
    # *malicious*.  the original implementation ignored the is_phishing flag,
    # so a benign message with high confidence produced a large final_score.
    # now we only count confidence when the AI predicts a phishing message.

    ai_out = {"confidence": 100, "is_phishing": True}
    scores = compute_scores(parsed, reputation, ai_out)
    assert scores["final_score"] == 100.0
    assert scores["malicious_ratio"] == 0.0
    assert scores["header_score"] == 0.0

    # explicit benign example – the final score should drop all the way to
    # zero when the AI is very confident the mail is safe.
    ai_out_benign = {"confidence": 95, "is_phishing": False}
    scores = compute_scores(parsed, reputation, ai_out_benign)
    assert scores["final_score"] == 0.0
    assert scores["malicious_ratio"] == 0.0
    assert scores["header_score"] == 0.0


def test_compute_scores_with_malicious_and_anomalies():
    """Scores should incorporate reputation and header anomalies but not drop
    below AI confidence."""
    parsed = {"spf": "fail", "dkim": "pass", "dmarc": "neutral"}
    # one malicious url in reputation
    reputation = {"urls": {"http://bad": {"virustotal": {"data": {"attributes": {"last_analysis_stats": {"malicious": 1}}}}}},
                  "domains": {}, "ips": {}}
    ai_out = {"confidence": 80, "is_phishing": True}
    scores = compute_scores(parsed, reputation, ai_out)

    # header score = 2/3 *100 = 66.67 -> rounded later
    assert scores["header_score"] == round((2 / 3) * 100, 2)
    # malicious_ratio = 1/1 = 1.0
    assert scores["malicious_ratio"] == 1.0
    # final should be at least ai confidence
    assert scores["final_score"] >= 80.0
    # with the weighting, final_score should be higher than ai_conf when other
    # signals are present
    assert scores["final_score"] > 80.0
