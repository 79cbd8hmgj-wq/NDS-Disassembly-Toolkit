from __future__ import annotations

from collections.abc import Sequence

from nds_disassembly_toolkit.analysis.model import (
    CFGEdgeKind,
    CrossReference,
    CrossReferenceKind,
    FunctionControlFlowGraph,
    PointerReference,
)


def _sort_key(reference: CrossReference) -> tuple[object, ...]:
    return (
        reference.source_component,
        reference.source_address,
        reference.kind.value,
        reference.source_function_address if reference.source_function_address is not None else -1,
        reference.source_instruction_set.value if reference.source_instruction_set is not None else "",
        reference.target_address,
        reference.target_instruction_set.value if reference.target_instruction_set is not None else "",
    )


def _sorted_unique(references: set[CrossReference]) -> tuple[CrossReference, ...]:
    return tuple(sorted(references, key=_sort_key))


def build_code_xrefs(
    cfgs: Sequence[FunctionControlFlowGraph],
) -> tuple[CrossReference, ...]:
    references: set[CrossReference] = set()
    for cfg in cfgs:
        block_modes = {block.address: block.instruction_set for block in cfg.blocks}
        for edge in cfg.edges:
            if edge.kind is CFGEdgeKind.FALLTHROUGH:
                continue
            kind = (
                CrossReferenceKind.CALL
                if edge.kind is CFGEdgeKind.CALL
                else CrossReferenceKind.BRANCH
            )
            references.add(
                CrossReference(
                    kind=kind,
                    source_component=cfg.function.component,
                    source_address=edge.source_instruction_address,
                    source_function_address=cfg.function.address,
                    source_instruction_set=block_modes.get(edge.source_address),
                    target_address=edge.target_address,
                    target_instruction_set=edge.target_instruction_set,
                )
            )
    return _sorted_unique(references)


def build_data_xrefs(
    references: Sequence[PointerReference],
) -> tuple[CrossReference, ...]:
    normalized = {
        CrossReference(
            kind=CrossReferenceKind.DATA_POINTER,
            source_component=reference.component,
            source_address=reference.address,
            source_function_address=None,
            source_instruction_set=None,
            target_address=reference.target_address,
            target_instruction_set=None,
        )
        for reference in references
    }
    return _sorted_unique(normalized)
