import yaml

from llmrt.evaluation import calculate_metrics, check_splits, evaluate


def test_denominators_include_abstention():
    rows = [
        dict(label=label, prediction=prediction, status=status)
        for label, prediction, status in [
            (True, True, "completed"),
            (True, None, "timeout"),
            (False, True, "completed"),
            (False, False, "completed"),
            (False, None, "target_error"),
            (True, None, "unsupported"),
        ]
    ]
    result = calculate_metrics(rows)
    assert result["precision"] == 0.5
    assert result["observed_recall"] == 0.5
    assert result["observed_fpr"] == 1 / 3
    assert result["conditional_fpr"] == 0.5
    assert result["counts"]["unsupported"] == 1
    assert calculate_metrics([])["precision"] is None


def test_dataset_groups_are_disjoint():
    from pathlib import Path

    root = Path(__file__).resolve().parents[1] / "evaluation"
    assert check_splits(
        [root / f"{name}.yaml" for name in ["development", "validation", "reference"]]
    )["disjoint_groups"]


async def test_reference_evaluation(demo, tmp_path):
    root, _, _ = demo
    suite = tmp_path / "suite.yaml"
    suite.write_text(
        yaml.safe_dump(
            {
                "suite_id": "test_suite",
                "split": "reference",
                "cases": [
                    dict(
                        id="positive",
                        target="vulnerable",
                        scenario="cross_user_basic",
                        violation=True,
                    ),
                    dict(
                        id="negative",
                        target="protected",
                        scenario="cross_user_basic",
                        violation=False,
                    ),
                ],
            }
        )
    )
    result = await evaluate(
        suite,
        {"vulnerable": root / "vulnerable.yaml", "protected": root / "protected.yaml"},
        tmp_path / "runs",
        runs=2,
    )
    assert len(result["per_run"]) == 2
    assert all(run["metrics"]["precision"] == 1 for run in result["per_run"])
    assert all(row["stable"] for row in result["stability"])


async def test_evaluation_budget_applies_across_cases_and_repeats(demo, tmp_path):
    root, lab, _ = demo
    suite = tmp_path / "suite.yaml"
    suite.write_text(
        yaml.safe_dump(
            {
                "suite_id": "budget_suite",
                "split": "reference",
                "cases": [
                    dict(
                        id="positive",
                        target="vulnerable",
                        scenario="cross_user_basic",
                        violation=True,
                    ),
                    dict(
                        id="negative",
                        target="protected",
                        scenario="cross_user_basic",
                        violation=False,
                    ),
                ],
            }
        )
    )
    result = await evaluate(
        suite,
        {"vulnerable": root / "vulnerable.yaml", "protected": root / "protected.yaml"},
        tmp_path / "runs",
        runs=2,
        budget_overrides={"max_requests": 5},
    )
    assert result["requests"] == 5
    assert sum(row["requests"] for row in result["observations"]) == 5
    assert any(row["status"] == "budget_exhausted" for row in result["observations"])
    assert not lab.contexts
