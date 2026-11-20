from app.services.benchmark import run_benchmark


def test_versioned_correlation_benchmark_passes():
    report = run_benchmark()
    assert report["passed"] is True
    assert report["scenario_count"] >= 10
    assert report["scenario_pass_rate"] == 1.0
    assert report["metrics"]["precision"] == 1.0
    assert report["metrics"]["recall"] == 1.0
    assert report["confusion_matrix"]["false_positive"] == 0
    assert report["confusion_matrix"]["false_negative"] == 0
    assert "not real-world calibration" in report["semantics"]
