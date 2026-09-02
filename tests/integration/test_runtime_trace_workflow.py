from __future__ import annotations

from collections import deque
from hashlib import sha256
from pathlib import Path

from nds_disassembly_toolkit.analysis import (
    BasicBlock,
    Component,
    ControlFlowKind,
    CrossReference,
    CrossReferenceKind,
    DecodedInstruction,
    FunctionCandidate,
    FunctionControlFlowGraph,
    InstructionSet,
    Symbol,
    SymbolKind,
    SymbolTable,
)
from nds_disassembly_toolkit.analysis.project import AnalysisProject, ComponentAnalysisBundle
from nds_disassembly_toolkit.analysis.runtime import (
    BreakpointKind,
    RegisterSnapshot,
    RuntimeCpu,
    RuntimeSnapshot,
    RuntimeStop,
    StopReasonKind,
)
from nds_disassembly_toolkit.analysis.runtime.capture import capture_trace
from nds_disassembly_toolkit.analysis.runtime.correlation import analysis_project_fingerprint
from nds_disassembly_toolkit.analysis.runtime.trace_diff import compare_traces, inspect_trace
from nds_disassembly_toolkit.analysis.runtime.trace_model import (
    TraceCaptureConfig,
    TraceCaptureMode,
    TraceMemoryRegion,
)

BASE = 0x02000000
MEMORY = 0x02100000


def _snapshot(pc: int) -> RuntimeSnapshot:
    return RuntimeSnapshot(
        cpu=RuntimeCpu.ARM9,
        registers=RegisterSnapshot.from_mapping({"pc": pc, "cpsr": 0x13}),
        stop=RuntimeStop(
            StopReasonKind.BREAKPOINT,
            signal=5,
            address=pc,
            raw="T05",
        ),
    )


class _CaptureSession:
    cpu = RuntimeCpu.ARM9

    def __init__(self, pc: int, before: bytes, after: bytes) -> None:
        self._snapshot = _snapshot(pc)
        self._memory = deque((before, after))

    def read_memory(self, address: int, length: int) -> bytes:
        assert address == MEMORY
        value = self._memory.popleft()
        assert len(value) == length
        return value

    def step(self) -> RuntimeSnapshot:
        raise AssertionError("single-event breakpoint capture must not step")

    def run_until_breakpoint(
        self,
        address: int,
        *,
        length: int = 4,
    ) -> RuntimeSnapshot:
        assert address == self._snapshot.pc
        assert length == 4
        return self._snapshot

    def run_until_watchpoint(
        self,
        kind: BreakpointKind,
        address: int,
        *,
        length: int = 4,
    ) -> RuntimeSnapshot:
        raise AssertionError("breakpoint workflow must not use a watchpoint")


def _instruction(address: int) -> DecodedInstruction:
    return DecodedInstruction(
        address=address,
        size=4,
        data=b"\x00\x00\xa0\xe1",
        mnemonic="mov",
        operands="r0, r0",
        instruction_set=InstructionSet.ARM,
        control_flow=ControlFlowKind.ORDINARY,
    )


def _cfg(function: FunctionCandidate) -> FunctionControlFlowGraph:
    return FunctionControlFlowGraph(
        function=function,
        blocks=(
            BasicBlock(
                component=function.component,
                address=function.address,
                offset=function.offset,
                instruction_set=InstructionSet.ARM,
                instructions=(
                    _instruction(function.address),
                    _instruction(function.address + 4),
                ),
            ),
        ),
        edges=(),
        unresolved_transfers=(),
        decode_failures=(),
    )


def _digest(path: Path) -> str:
    return sha256(path.read_bytes()).hexdigest()


def test_real_project_capture_inspect_and_diff_workflow(tmp_path: Path) -> None:
    function = FunctionCandidate(
        component="arm9",
        address=BASE + 0x20,
        offset=0x20,
        instruction_set=InstructionSet.ARM,
        confidence="high",
        evidence=("integration",),
    )
    component = Component("arm9", Path("arm9.bin"), BASE, bytes(0x100))
    symbol = Symbol(
        component="arm9",
        address=function.address,
        offset=function.offset,
        name="target_function",
        kind=SymbolKind.FUNCTION,
        instruction_set=InstructionSet.ARM,
        confidence="high",
        evidence=("integration",),
    )
    memory_reference = CrossReference(
        kind=CrossReferenceKind.DATA_POINTER,
        source_component="arm9",
        source_address=function.address + 4,
        source_function_address=function.address,
        source_instruction_set=InstructionSet.ARM,
        target_address=MEMORY + 1,
        target_instruction_set=None,
    )

    project_path = tmp_path / "game.ndsre"
    with AnalysisProject.create(project_path) as project:
        project.store_component_analysis(
            ComponentAnalysisBundle(
                component=component,
                functions=(function,),
                cfgs=(_cfg(function),),
                xrefs=(memory_reference,),
                symbols=SymbolTable((symbol,)),
            )
        )

    with AnalysisProject.open(project_path, read_only=True) as project:
        fingerprint = analysis_project_fingerprint(project)

    region = TraceMemoryRegion(0, MEMORY, 4, "state")
    baseline_path = tmp_path / "baseline.ndstrace"
    target_path = tmp_path / "target.ndstrace"
    baseline_config = TraceCaptureConfig(
        cpu=RuntimeCpu.ARM9,
        mode=TraceCaptureMode.BREAKPOINT,
        limit=1,
        timeout=5.0,
        condition_kind=BreakpointKind.CODE,
        condition_address=BASE + 0x80,
        condition_length=4,
        memory_regions=(region,),
        project_fingerprint=fingerprint,
    )
    target_config = TraceCaptureConfig(
        cpu=RuntimeCpu.ARM9,
        mode=TraceCaptureMode.BREAKPOINT,
        limit=1,
        timeout=5.0,
        condition_kind=BreakpointKind.CODE,
        condition_address=function.address,
        condition_length=4,
        memory_regions=(region,),
        project_fingerprint=fingerprint,
    )

    capture_trace(
        _CaptureSession(BASE + 0x80, b"AAAA", b"AAAA"),
        baseline_config,
        baseline_path,
    )
    capture_trace(
        _CaptureSession(function.address, b"AAAA", b"ABAA"),
        target_config,
        target_path,
    )
    before_hashes = (_digest(baseline_path), _digest(target_path))

    with AnalysisProject.open(project_path, read_only=True) as project:
        inspection = inspect_trace(target_path, project=project)
        report = compare_traces(baseline_path, target_path, project=project)

    assert inspection.integrity_ok is True
    assert inspection.evidence_events == 1
    assert inspection.memory_changes
    assert inspection.memory_changes[0].address == MEMORY + 1
    assert inspection.memory_changes[0].before == b"A"
    assert inspection.memory_changes[0].after == b"B"
    assert inspection.addresses[0].correlation is not None
    assert inspection.addresses[0].correlation.resolved_function == function

    assert report.target_identity_verified is True
    target_delta = next(
        delta for delta in report.function_deltas if delta.address == function.address
    )
    assert target_delta.classification == "target_only"
    assert target_delta.changed_memory_references == (memory_reference,)
    assert report.rankings[0].address == function.address
    evidence = {item.name: item.value for item in report.rankings[0].evidence}
    assert evidence["target_exclusive"] == 1.0
    assert evidence["positive_frequency_delta"] == 1.0
    assert evidence["condition_hit"] == 1.0
    assert evidence["changed_memory_reference"] == 1.0

    assert (_digest(baseline_path), _digest(target_path)) == before_hashes
