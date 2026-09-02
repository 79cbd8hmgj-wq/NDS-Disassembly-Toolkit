from __future__ import annotations

from pathlib import Path

from nds_disassembly_toolkit.analysis import (
    Component,
    FunctionCandidate,
    InstructionSet,
    Symbol,
    SymbolKind,
    SymbolTable,
)
from nds_disassembly_toolkit.analysis.project import (
    AnalysisProject,
    ComponentAnalysisBundle,
    LocationAnnotation,
)
from nds_disassembly_toolkit.analysis.runtime import (
    RegisterSnapshot,
    RuntimeCpu,
    RuntimeSnapshot,
    RuntimeStop,
    StopReasonKind,
    correlate_snapshot,
)


def _snapshot(pc: int, *, thumb: bool = False) -> RuntimeSnapshot:
    cpsr = 0x13 | ((1 << 5) if thumb else 0)
    return RuntimeSnapshot(
        cpu=RuntimeCpu.ARM9,
        registers=RegisterSnapshot.from_mapping({"pc": pc, "cpsr": cpsr}),
        stop=RuntimeStop(StopReasonKind.BREAKPOINT, address=pc),
    )


def _function(component: str, address: int, mode: InstructionSet) -> FunctionCandidate:
    return FunctionCandidate(
        component=component,
        address=address,
        offset=0x20,
        instruction_set=mode,
        confidence="high",
        evidence=("seed",),
    )


def _symbol(component: str, address: int, mode: InstructionSet) -> Symbol:
    return Symbol(
        component=component,
        address=address,
        offset=0x20,
        name=f"{component}_entry",
        kind=SymbolKind.FUNCTION,
        instruction_set=mode,
        confidence="high",
        evidence=("function",),
    )


def test_correlate_snapshot_includes_exact_function_symbols_and_annotation(
    tmp_path: Path,
) -> None:
    base = 0x02000000
    pc = base + 0x20
    component = Component("arm9", Path("arm9.bin"), base, bytes(0x100))
    function = _function("arm9", pc, InstructionSet.ARM)
    symbol = _symbol("arm9", pc, InstructionSet.ARM)
    annotation = LocationAnnotation(
        "arm9",
        pc,
        name_override="MainLoop",
        comment="runtime target",
        tags=("runtime",),
        bookmarked=True,
    )

    with AnalysisProject.create(tmp_path / "game.ndsre") as project:
        project.store_component_analysis(
            ComponentAnalysisBundle(
                component,
                functions=(function,),
                symbols=SymbolTable((symbol,)),
            )
        )
        project.set_annotation(annotation)

        location = correlate_snapshot(project, _snapshot(pc))

    assert location.pc == pc
    assert location.instruction_set is InstructionSet.ARM
    assert len(location.candidates) == 1
    candidate = location.candidates[0]
    assert candidate.component == "arm9"
    assert candidate.function == function
    assert candidate.symbols == (symbol,)
    assert candidate.annotation == annotation


def test_correlate_snapshot_uses_exact_arm_thumb_function_identity(tmp_path: Path) -> None:
    base = 0x02000000
    pc = base + 0x20
    component = Component("arm9", Path("arm9.bin"), base, bytes(0x100))
    arm = _function("arm9", pc, InstructionSet.ARM)
    thumb = _function("arm9", pc, InstructionSet.THUMB)

    with AnalysisProject.create(tmp_path / "game.ndsre") as project:
        project.store_component_analysis(
            ComponentAnalysisBundle(component, functions=(arm, thumb))
        )
        location = correlate_snapshot(project, _snapshot(pc, thumb=True))

    assert location.candidates[0].function == thumb


def test_correlate_snapshot_outside_all_components_has_no_candidates(
    tmp_path: Path,
) -> None:
    component = Component("arm9", Path("arm9.bin"), 0x02000000, bytes(0x100))
    with AnalysisProject.create(tmp_path / "game.ndsre") as project:
        project.store_component_analysis(ComponentAnalysisBundle(component))
        location = correlate_snapshot(project, _snapshot(0x03000000))

    assert location.candidates == ()


def test_correlate_snapshot_preserves_overlapping_overlay_candidates(
    tmp_path: Path,
) -> None:
    base = 0x02200000
    pc = base + 0x20
    overlay_3 = Component("overlay_3", Path("overlay_3.bin"), base, bytes(0x80))
    overlay_7 = Component("overlay_7", Path("overlay_7.bin"), base, bytes(0x80))
    function_3 = _function("overlay_3", pc, InstructionSet.ARM)
    function_7 = _function("overlay_7", pc, InstructionSet.ARM)

    with AnalysisProject.create(tmp_path / "game.ndsre") as project:
        project.store_component_analysis(
            ComponentAnalysisBundle(overlay_7, functions=(function_7,))
        )
        project.store_component_analysis(
            ComponentAnalysisBundle(overlay_3, functions=(function_3,))
        )
        location = correlate_snapshot(project, _snapshot(pc))

    assert tuple(candidate.component for candidate in location.candidates) == (
        "overlay_3",
        "overlay_7",
    )
    assert tuple(candidate.function for candidate in location.candidates) == (
        function_3,
        function_7,
    )
