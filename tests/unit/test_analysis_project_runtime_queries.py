from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

import nds_disassembly_toolkit.analysis.runtime.correlation as runtime_correlation
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
)
from nds_disassembly_toolkit.analysis.project import (
    AnalysisProject,
    ComponentAnalysisBundle,
    LocationAnnotation,
)

BASE = 0x02000000


def _function(address: int) -> FunctionCandidate:
    return FunctionCandidate(
        component="arm9",
        address=address,
        offset=address - BASE,
        instruction_set=InstructionSet.ARM,
        confidence="high",
        evidence=("test",),
    )


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


def _cfg(
    function: FunctionCandidate,
    instruction_addresses: tuple[int, ...],
) -> FunctionControlFlowGraph:
    block_address = min(instruction_addresses)
    return FunctionControlFlowGraph(
        function=function,
        blocks=(
            BasicBlock(
                component="arm9",
                address=block_address,
                offset=block_address - BASE,
                instruction_set=InstructionSet.ARM,
                instructions=tuple(_instruction(address) for address in instruction_addresses),
            ),
        ),
        edges=(),
        unresolved_transfers=(),
        decode_failures=(),
    )


def test_functions_containing_uses_persisted_instruction_ownership(tmp_path: Path) -> None:
    root = tmp_path / "game.ndsre"
    component = Component("arm9", Path("arm9.bin"), BASE, bytes(0x100))
    function = _function(BASE)
    cfg = _cfg(function, (BASE, BASE + 4, BASE + 8))

    with AnalysisProject.create(root) as project:
        project.store_component_analysis(
            ComponentAnalysisBundle(component, functions=(function,), cfgs=(cfg,))
        )
        assert project.function("arm9", BASE + 4, InstructionSet.ARM) is None
        assert project.functions_containing(
            "arm9", BASE + 4, InstructionSet.ARM
        ) == (function,)


def test_functions_containing_preserves_ambiguous_function_claims(tmp_path: Path) -> None:
    root = tmp_path / "game.ndsre"
    component = Component("arm9", Path("arm9.bin"), BASE, bytes(0x100))
    first = _function(BASE)
    second = _function(BASE + 0x20)
    first_cfg = _cfg(first, (BASE, BASE + 4))
    second_cfg = _cfg(second, (BASE + 4,))

    with AnalysisProject.create(root) as project:
        project.store_component_analysis(
            ComponentAnalysisBundle(
                component,
                functions=(first, second),
                cfgs=(first_cfg, second_cfg),
            )
        )
        assert project.functions_containing(
            "arm9", BASE + 4, InstructionSet.ARM
        ) == (first, second)


def test_runtime_xref_range_and_function_queries_are_precise(tmp_path: Path) -> None:
    root = tmp_path / "game.ndsre"
    component = Component("arm9", Path("arm9.bin"), BASE, bytes(0x100))
    first = _function(BASE)
    second = _function(BASE + 0x20)
    first_ref = CrossReference(
        kind=CrossReferenceKind.DATA_POINTER,
        source_component="arm9",
        source_address=BASE + 4,
        source_function_address=BASE,
        source_instruction_set=InstructionSet.ARM,
        target_address=0x02100000,
        target_instruction_set=None,
    )
    second_ref = CrossReference(
        kind=CrossReferenceKind.CALL,
        source_component="arm9",
        source_address=BASE + 0x24,
        source_function_address=BASE + 0x20,
        source_instruction_set=InstructionSet.ARM,
        target_address=0x0210000F,
        target_instruction_set=InstructionSet.ARM,
    )
    excluded_end = CrossReference(
        kind=CrossReferenceKind.BRANCH,
        source_component="arm9",
        source_address=BASE + 0x28,
        source_function_address=BASE + 0x20,
        source_instruction_set=InstructionSet.ARM,
        target_address=0x02100010,
        target_instruction_set=InstructionSet.ARM,
    )
    overlay = Component("overlay_1", Path("overlay_1.bin"), 0x02200000, bytes(0x40))
    overlay_ref = CrossReference(
        kind=CrossReferenceKind.DATA_POINTER,
        source_component="overlay_1",
        source_address=0x02200000,
        source_function_address=None,
        source_instruction_set=None,
        target_address=0x02100008,
        target_instruction_set=None,
    )

    with AnalysisProject.create(root) as project:
        project.store_component_analysis(
            ComponentAnalysisBundle(
                component,
                functions=(first, second),
                xrefs=(excluded_end, second_ref, first_ref),
            )
        )
        project.store_component_analysis(
            ComponentAnalysisBundle(overlay, xrefs=(overlay_ref,))
        )

        assert project.xrefs_to_range(0x02100000, 0x02100010) == (
            first_ref,
            overlay_ref,
            second_ref,
        )
        assert project.xrefs_to_range(
            0x02100000, 0x02100010, source_component="arm9"
        ) == (first_ref, second_ref)
        assert project.xrefs_from_function(
            "arm9", BASE, InstructionSet.ARM
        ) == (first_ref,)
        assert project.xrefs_from_function(
            "arm9", BASE + 0x20, InstructionSet.ARM
        ) == (second_ref, excluded_end)

        with pytest.raises(ValueError, match="end address"):
            project.xrefs_to_range(0x02100000, 0x02100000)


def _canonical_fingerprint(project: AnalysisProject) -> str:
    metadata = project.metadata
    payload = {
        "analysis_model_version": metadata.analysis_model_version,
        "components": [
            {
                "base_address": item.base_address,
                "name": item.name,
                "sha256": item.sha256,
                "size": item.size,
            }
            for item in project.component_identities()
        ],
        "project_format_version": metadata.project_format_version,
        "schema_version": metadata.schema_version,
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )
    return hashlib.sha256(encoded).hexdigest()


def test_analysis_project_fingerprint_is_exact_and_ignores_annotations(
    tmp_path: Path,
) -> None:
    root = tmp_path / "game.ndsre"
    component = Component("arm9", Path("arm9.bin"), BASE, bytes(range(0x40)))

    with AnalysisProject.create(root) as project:
        project.store_component_analysis(ComponentAnalysisBundle(component))
        expected = _canonical_fingerprint(project)
        before = runtime_correlation.analysis_project_fingerprint(project)
        project.set_annotation(
            LocationAnnotation(
                "arm9",
                BASE,
                name_override="entry",
                comment="derived user note",
                tags=("runtime",),
                bookmarked=True,
            )
        )
        after = runtime_correlation.analysis_project_fingerprint(project)

        assert before == expected
        assert after == expected
        assert project.metadata.schema_version == 1
        assert project.metadata.analysis_model_version == 1


def test_analysis_project_fingerprint_changes_with_component_identity(
    tmp_path: Path,
) -> None:
    first_root = tmp_path / "first.ndsre"
    second_root = tmp_path / "second.ndsre"

    with AnalysisProject.create(first_root) as first_project:
        first_project.store_component_analysis(
            ComponentAnalysisBundle(
                Component("arm9", Path("arm9.bin"), BASE, bytes(0x40))
            )
        )
        first = runtime_correlation.analysis_project_fingerprint(first_project)

    with AnalysisProject.create(second_root) as second_project:
        second_project.store_component_analysis(
            ComponentAnalysisBundle(
                Component("arm9", Path("arm9.bin"), BASE, b"\x01" + bytes(0x3F))
            )
        )
        second = runtime_correlation.analysis_project_fingerprint(second_project)

    assert first != second
