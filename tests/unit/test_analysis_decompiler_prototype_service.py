from __future__ import annotations

import pytest

from nds_disassembly_toolkit.analysis.decompiler import prototype_service
from nds_disassembly_toolkit.analysis.decompiler.model import (
    DecompiledBlock,
    DecompiledFunction,
    ReturnStatement,
    SourceRef,
)
from nds_disassembly_toolkit.analysis.decompiler.type_model import VoidType
from nds_disassembly_toolkit.analysis.decompiler.type_propagation import (
    FunctionTypeIdentity,
)
from nds_disassembly_toolkit.analysis.model import (
    FunctionCandidate,
    InstructionSet,
)

BASE = 0x0200C000


def _source(address: int) -> tuple[SourceRef, ...]:
    return (SourceRef(address, InstructionSet.ARM),)


def _function(address: int, *, component: str = "arm9") -> FunctionCandidate:
    return FunctionCandidate(
        component,
        address,
        address - BASE,
        InstructionSet.ARM,
        "high",
        ("test",),
    )


def _lifted(function: FunctionCandidate) -> DecompiledFunction:
    source = _source(function.address)
    return DecompiledFunction(
        component=function.component,
        address=function.address,
        instruction_set=function.instruction_set,
        name=f"sub_{function.address:08X}",
        parameters=(),
        locals=(),
        blocks=(
            DecompiledBlock(
                function.address,
                function.instruction_set,
                (ReturnStatement(None, source),),
                (),
            ),
        ),
    )


class _ProjectStub:
    def __init__(
        self,
        functions: tuple[FunctionCandidate, ...],
        *,
        missing_cfg: frozenset[int] = frozenset(),
        missing_flow: frozenset[int] = frozenset(),
    ) -> None:
        self._functions = functions
        self._missing_cfg = missing_cfg
        self._missing_flow = missing_flow
        self.write_attempted = False

    def functions(self) -> tuple[FunctionCandidate, ...]:
        return self._functions

    def cfg(
        self,
        component: str,
        address: int,
        instruction_set: InstructionSet,
    ) -> object | None:
        del component, instruction_set
        return None if address in self._missing_cfg else object()

    def data_flow(
        self,
        component: str,
        address: int,
        instruction_set: InstructionSet,
    ) -> object | None:
        del component, instruction_set
        return None if address in self._missing_flow else object()

    def store_component_analysis(self, bundle: object) -> None:
        del bundle
        self.write_attempted = True
        raise AssertionError("prototype service must remain read-only")


def _patch_lift(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        prototype_service,
        "build_name_context",
        lambda *args: object(),
    )
    monkeypatch.setattr(
        prototype_service,
        "lift_function",
        lambda project, function, cfg, flow, names: _lifted(function),
    )


def test_project_prototype_service_is_deterministic_and_read_only(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_lift(monkeypatch)
    first_function = _function(BASE)
    second_function = _function(BASE + 0x100)
    project = _ProjectStub((second_function, first_function))

    first = prototype_service.recover_project_prototypes(  # type: ignore[arg-type]
        project
    )
    second = prototype_service.recover_project_prototypes(  # type: ignore[arg-type]
        project
    )

    assert first == second
    assert project.write_attempted is False
    assert first.diagnostics == ()
    assert tuple(
        prototype.identity.address
        for prototype in first.propagation.prototypes
    ) == (BASE, BASE + 0x100)
    assert all(
        isinstance(prototype.return_type, VoidType)
        for prototype in first.propagation.prototypes
    )


def test_project_prototype_service_skips_missing_cfg_with_diagnostic(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_lift(monkeypatch)
    missing = _function(BASE)
    healthy = _function(BASE + 0x100)
    project = _ProjectStub(
        (missing, healthy),
        missing_cfg=frozenset({missing.address}),
    )

    result = prototype_service.recover_project_prototypes(  # type: ignore[arg-type]
        project
    )

    assert tuple(
        prototype.identity.address
        for prototype in result.propagation.prototypes
    ) == (healthy.address,)
    assert result.diagnostics == (
        prototype_service.PrototypeServiceDiagnostic(
            FunctionTypeIdentity(
                "arm9",
                missing.address,
                InstructionSet.ARM,
            ),
            "missing persisted CFG",
        ),
    )


def test_project_prototype_service_skips_missing_flow_with_diagnostic(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_lift(monkeypatch)
    missing = _function(BASE)
    project = _ProjectStub(
        (missing,),
        missing_flow=frozenset({missing.address}),
    )

    result = prototype_service.recover_project_prototypes(  # type: ignore[arg-type]
        project
    )

    assert result.propagation.prototypes == ()
    assert result.diagnostics == (
        prototype_service.PrototypeServiceDiagnostic(
            FunctionTypeIdentity(
                "arm9",
                missing.address,
                InstructionSet.ARM,
            ),
            "missing persisted data flow",
        ),
    )


def test_project_prototype_service_exposes_analyzed_ssa_and_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_lift(monkeypatch)
    function = _function(BASE)
    project = _ProjectStub((function,))

    result = prototype_service.recover_project_prototypes(  # type: ignore[arg-type]
        project
    )
    identity = FunctionTypeIdentity(
        "arm9",
        BASE,
        InstructionSet.ARM,
    )

    ssa = result.ssa_for(identity)
    environment = result.environment_for(identity)

    assert ssa is not None
    assert ssa.address == BASE
    assert environment is not None
