"""Pytest wrapper around the spoliation harness — the submission's headline guarantee."""

from __future__ import annotations

from pathlib import Path

import pytest

from linuxir.config import CaseConfig
from linuxir.guardrails import spoliation_test as st
from linuxir.guardrails.constraints import ConstraintEnforcer, SpoliationViolation


@pytest.fixture
def case(tmp_path: Path) -> CaseConfig:
    c = CaseConfig(
        case_id="spoliation-pytest",
        evidence_scope=(Path("/mnt/evidence"),),
        workspace=tmp_path,
    )
    c.ensure_workspace()
    return c


def test_all_ten_attacks_blocked_and_logged(case: CaseConfig) -> None:
    results = st.run(case)
    assert len(results) == 10
    assert all(r.blocked_via_gateway for r in results), [
        r.attack.label for r in results if not r.blocked_via_gateway
    ]
    assert all(r.raises_directly for r in results), [
        r.attack.label for r in results if not r.raises_directly
    ]
    assert st._count_logged(case) == 10


@pytest.mark.parametrize("attack", st.ATTACKS, ids=lambda a: f"attack-{a.n}")
def test_each_attack_raises(case: CaseConfig, attack: st.Attack) -> None:
    enforcer = ConstraintEnforcer(case.evidence_scope, case.writable_roots)
    with pytest.raises(SpoliationViolation):
        enforcer.check(
            attack.tool,
            attack.tool_input,
            is_registered=attack.registered,
            path_params=attack.path_params,
            command_params=attack.command_params,
            arg_params=attack.arg_params,
        )


def test_legitimate_reads_are_permitted(case: CaseConfig) -> None:
    """The enforcer must not be so strict it blocks valid in-scope reads."""
    enforcer = ConstraintEnforcer(case.evidence_scope, case.writable_roots)
    # cat / grep within scope, and a typed read within scope — none should raise.
    enforcer.check(
        "bash_readonly",
        {"command": "grep -i Accepted /mnt/evidence/var/log/auth.log"},
        is_registered=True,
        command_params=("command",),
    )
    enforcer.check(
        "read_evidence_file",
        {"path": "/mnt/evidence/home/user/.bash_history"},
        is_registered=True,
        path_params=("path",),
    )


def test_main_returns_zero() -> None:
    assert st.main() == 0
