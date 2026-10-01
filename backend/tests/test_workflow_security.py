from __future__ import annotations

import sys
from pathlib import Path

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))
import check_workflow_security as policy


def test_workflow_duplicate_environment_is_rejected_even_when_values_overlap():
    with pytest.raises(yaml.YAMLError, match="duplicate key 'env'"):
        policy.workflow_references(
            "steps:\n  - env: {TAG: value}\n    run: true\n    env: {TAG: value, SHA: other}\n"
        )


@pytest.mark.parametrize("owner", ["gitleaks", "docker", "anchore", "aquasecurity"])
def test_third_party_action_is_rejected_in_flow_style_mapping(tmp_path, monkeypatch, owner):
    workflow = tmp_path / "test.yml"
    workflow.write_text("jobs: {scan: {uses: " + owner + "/action@" + "a" * 40 + "}}\n")
    monkeypatch.setattr(policy, "ROOT", tmp_path)
    monkeypatch.setattr(policy, "WORKFLOWS", tmp_path)
    monkeypatch.setattr(policy, "REQUIRED_MAIN_PUSH_WORKFLOWS", ())
    assert policy.main() == 1


def test_parser_keeps_on_as_a_string_and_finds_reusable_workflow_references():
    document = yaml.load("on: {push: {branches: [main]}}\n", Loader=policy.UniqueKeyLoader)
    assert "on" in document
    assert policy.workflow_references("jobs: {test: {uses: actions/test@" + "a" * 40 + "}}") == [
        "actions/test@" + "a" * 40
    ]
