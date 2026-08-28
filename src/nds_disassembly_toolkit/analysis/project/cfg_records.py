from __future__ import annotations

import json
import sqlite3

from nds_disassembly_toolkit.analysis.model import (
    BasicBlock,
    CFGEdge,
    CFGEdgeKind,
    ConditionCode,
    ControlFlowKind,
    DecodedInstruction,
    FunctionCandidate,
    FunctionControlFlowGraph,
    InstructionOperand,
    InstructionSemantics,
    InstructionSet,
    MemoryOperand,
    OperandAccess,
    OperandKind,
    OperandShift,
    Register,
    ShiftKind,
    UnresolvedTransfer,
)
from nds_disassembly_toolkit.analysis.project.model import ComponentAnalysisBundle
from nds_disassembly_toolkit.errors import AnalysisProjectError


def _register_value(register: Register | None) -> str | None:
    return None if register is None else register.value


def _dump_operand(operand: InstructionOperand) -> dict[str, object]:
    memory: dict[str, object] | None = None
    if operand.memory is not None:
        memory = {
            "base": _register_value(operand.memory.base),
            "index": _register_value(operand.memory.index),
            "scale": operand.memory.scale,
            "displacement": operand.memory.displacement,
            "subtract_index": operand.memory.subtract_index,
        }
    return {
        "kind": operand.kind.value,
        "access": int(operand.access),
        "register": _register_value(operand.register),
        "registers": [register.value for register in operand.registers],
        "immediate": operand.immediate,
        "memory": memory,
        "shift": {
            "kind": operand.shift.kind.value,
            "value": operand.shift.value,
        },
        "access_width": operand.access_width,
    }


def dump_semantics(semantics: InstructionSemantics) -> str:
    payload = {
        "operands": [_dump_operand(operand) for operand in semantics.operands],
        "registers_read": [register.value for register in semantics.registers_read],
        "registers_written": [register.value for register in semantics.registers_written],
        "condition": semantics.condition.value,
        "writeback": semantics.writeback,
    }
    return json.dumps(payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def _optional_register(value: object) -> Register | None:
    if value is None:
        return None
    return Register(str(value))


def _load_operand(value: object) -> InstructionOperand:
    if not isinstance(value, dict):
        raise ValueError("operand is not an object")
    memory_value = value["memory"]
    memory: MemoryOperand | None = None
    if memory_value is not None:
        if not isinstance(memory_value, dict):
            raise ValueError("memory operand is not an object")
        memory = MemoryOperand(
            base=_optional_register(memory_value["base"]),
            index=_optional_register(memory_value["index"]),
            scale=int(memory_value["scale"]),
            displacement=int(memory_value["displacement"]),
            subtract_index=bool(memory_value["subtract_index"]),
        )
    shift_value = value["shift"]
    if not isinstance(shift_value, dict):
        raise ValueError("operand shift is not an object")
    registers_value = value["registers"]
    if not isinstance(registers_value, list):
        raise ValueError("operand register list is invalid")
    immediate_value = value["immediate"]
    access_width_value = value["access_width"]
    return InstructionOperand(
        kind=OperandKind(str(value["kind"])),
        access=OperandAccess(int(value["access"])),
        register=_optional_register(value["register"]),
        registers=tuple(Register(str(register)) for register in registers_value),
        immediate=None if immediate_value is None else int(immediate_value),
        memory=memory,
        shift=OperandShift(
            kind=ShiftKind(str(shift_value["kind"])),
            value=int(shift_value["value"]),
        ),
        access_width=(
            None if access_width_value is None else int(access_width_value)
        ),
    )


def load_semantics(value: str) -> InstructionSemantics:
    try:
        decoded = json.loads(value)
        if not isinstance(decoded, dict):
            raise ValueError("semantics is not an object")
        operands_value = decoded["operands"]
        read_value = decoded["registers_read"]
        written_value = decoded["registers_written"]
        if not isinstance(operands_value, list):
            raise ValueError("semantics operands are invalid")
        if not isinstance(read_value, list) or not isinstance(written_value, list):
            raise ValueError("semantics registers are invalid")
        return InstructionSemantics(
            operands=tuple(_load_operand(item) for item in operands_value),
            registers_read=tuple(Register(str(item)) for item in read_value),
            registers_written=tuple(Register(str(item)) for item in written_value),
            condition=ConditionCode(str(decoded["condition"])),
            writeback=bool(decoded["writeback"]),
        )
    except (json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
        raise AnalysisProjectError("persisted instruction semantics are invalid") from exc


def validate_cfg_bundle(bundle: ComponentAnalysisBundle) -> None:
    functions = set(bundle.functions)
    for cfg in bundle.cfgs:
        if cfg.function not in functions:
            raise AnalysisProjectError(
                "bundle CFG function is not present in bundle functions"
            )
        for block in cfg.blocks:
            if block.component != bundle.component.name:
                raise AnalysisProjectError("bundle CFG block component is inconsistent")
            try:
                expected_offset = bundle.component.offset_for_address(block.address)
            except ValueError as exc:
                raise AnalysisProjectError("bundle CFG block address is outside component") from exc
            if block.offset != expected_offset:
                raise AnalysisProjectError("bundle CFG block offset is inconsistent")


def delete_cfgs(connection: sqlite3.Connection, component_id_value: int) -> None:
    connection.execute(
        "DELETE FROM basic_blocks WHERE component_id = ?",
        (component_id_value,),
    )
    connection.execute(
        "DELETE FROM cfg_edges WHERE component_id = ?",
        (component_id_value,),
    )
    connection.execute(
        "DELETE FROM unresolved_transfers WHERE component_id = ?",
        (component_id_value,),
    )
    connection.execute(
        "DELETE FROM decode_failures WHERE component_id = ?",
        (component_id_value,),
    )


def insert_cfgs(
    connection: sqlite3.Connection,
    component_id_value: int,
    cfgs: tuple[FunctionControlFlowGraph, ...],
) -> None:
    for cfg in cfgs:
        key = (
            component_id_value,
            cfg.function.address,
            cfg.function.instruction_set.value,
        )
        for block_ordinal, block in enumerate(cfg.blocks):
            connection.execute(
                """
                INSERT INTO basic_blocks(
                    component_id,
                    function_address,
                    function_instruction_set,
                    address,
                    offset,
                    instruction_set,
                    ordinal
                ) VALUES(?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    *key,
                    block.address,
                    block.offset,
                    block.instruction_set.value,
                    block_ordinal,
                ),
            )
            for instruction_ordinal, instruction in enumerate(block.instructions):
                connection.execute(
                    """
                    INSERT INTO instructions(
                        component_id,
                        function_address,
                        function_instruction_set,
                        block_address,
                        block_instruction_set,
                        address,
                        ordinal,
                        size,
                        data_hex,
                        mnemonic,
                        operands,
                        instruction_set,
                        control_flow,
                        direct_target,
                        target_instruction_set,
                        conditional,
                        semantics_json
                    ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        *key,
                        block.address,
                        block.instruction_set.value,
                        instruction.address,
                        instruction_ordinal,
                        instruction.size,
                        instruction.data.hex(),
                        instruction.mnemonic,
                        instruction.operands,
                        instruction.instruction_set.value,
                        instruction.control_flow.value,
                        instruction.direct_target,
                        (
                            None
                            if instruction.target_instruction_set is None
                            else instruction.target_instruction_set.value
                        ),
                        int(instruction.conditional),
                        dump_semantics(instruction.semantics),
                    ),
                )
        for edge in cfg.edges:
            connection.execute(
                """
                INSERT INTO cfg_edges(
                    component_id,
                    function_address,
                    function_instruction_set,
                    source_address,
                    source_instruction_address,
                    target_address,
                    target_instruction_set,
                    kind
                ) VALUES(?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    *key,
                    edge.source_address,
                    edge.source_instruction_address,
                    edge.target_address,
                    edge.target_instruction_set.value,
                    edge.kind.value,
                ),
            )
        for transfer in cfg.unresolved_transfers:
            connection.execute(
                """
                INSERT INTO unresolved_transfers(
                    component_id,
                    function_address,
                    function_instruction_set,
                    source_address,
                    instruction_set,
                    control_flow,
                    mnemonic,
                    operands
                ) VALUES(?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    *key,
                    transfer.source_address,
                    transfer.instruction_set.value,
                    transfer.control_flow.value,
                    transfer.mnemonic,
                    transfer.operands,
                ),
            )
        for address in cfg.decode_failures:
            connection.execute(
                """
                INSERT INTO decode_failures(
                    component_id,
                    function_address,
                    function_instruction_set,
                    address
                ) VALUES(?, ?, ?, ?)
                """,
                (*key, address),
            )


def _optional_instruction_set(value: object) -> InstructionSet | None:
    if value is None:
        return None
    return InstructionSet(str(value))


def _instruction_from_row(row: sqlite3.Row) -> DecodedInstruction:
    try:
        return DecodedInstruction(
            address=int(row["address"]),
            size=int(row["size"]),
            data=bytes.fromhex(str(row["data_hex"])),
            mnemonic=str(row["mnemonic"]),
            operands=str(row["operands"]),
            instruction_set=InstructionSet(str(row["instruction_set"])),
            control_flow=ControlFlowKind(str(row["control_flow"])),
            direct_target=(
                None if row["direct_target"] is None else int(row["direct_target"])
            ),
            target_instruction_set=_optional_instruction_set(
                row["target_instruction_set"]
            ),
            conditional=bool(row["conditional"]),
            semantics=load_semantics(str(row["semantics_json"])),
        )
    except (TypeError, ValueError) as exc:
        raise AnalysisProjectError("persisted instruction record is invalid") from exc


def cfg_from_database(
    connection: sqlite3.Connection,
    function: FunctionCandidate,
) -> FunctionControlFlowGraph | None:
    key = (
        function.component,
        function.address,
        function.instruction_set.value,
    )
    block_rows = connection.execute(
        """
        SELECT basic_blocks.address, basic_blocks.offset,
               basic_blocks.instruction_set
        FROM basic_blocks
        JOIN components ON components.id = basic_blocks.component_id
        WHERE components.name = ?
          AND basic_blocks.function_address = ?
          AND basic_blocks.function_instruction_set = ?
        ORDER BY basic_blocks.ordinal
        """,
        key,
    ).fetchall()
    if not block_rows:
        return None

    blocks: list[BasicBlock] = []
    for block_row in block_rows:
        block_address = int(block_row["address"])
        block_instruction_set = str(block_row["instruction_set"])
        instruction_rows = connection.execute(
            """
            SELECT instructions.address, instructions.size, instructions.data_hex,
                   instructions.mnemonic, instructions.operands,
                   instructions.instruction_set, instructions.control_flow,
                   instructions.direct_target, instructions.target_instruction_set,
                   instructions.conditional, instructions.semantics_json
            FROM instructions
            JOIN components ON components.id = instructions.component_id
            WHERE components.name = ?
              AND instructions.function_address = ?
              AND instructions.function_instruction_set = ?
              AND instructions.block_address = ?
              AND instructions.block_instruction_set = ?
            ORDER BY instructions.ordinal
            """,
            (*key, block_address, block_instruction_set),
        ).fetchall()
        try:
            block = BasicBlock(
                component=function.component,
                address=block_address,
                offset=int(block_row["offset"]),
                instruction_set=InstructionSet(block_instruction_set),
                instructions=tuple(
                    _instruction_from_row(row) for row in instruction_rows
                ),
            )
        except ValueError as exc:
            raise AnalysisProjectError("persisted CFG basic block is invalid") from exc
        blocks.append(block)

    edge_rows = connection.execute(
        """
        SELECT source_address, source_instruction_address, target_address,
               target_instruction_set, kind
        FROM cfg_edges
        JOIN components ON components.id = cfg_edges.component_id
        WHERE components.name = ?
          AND cfg_edges.function_address = ?
          AND cfg_edges.function_instruction_set = ?
        ORDER BY source_address, source_instruction_address, target_address,
                 target_instruction_set, kind
        """,
        key,
    ).fetchall()
    transfer_rows = connection.execute(
        """
        SELECT source_address, instruction_set, control_flow, mnemonic, operands
        FROM unresolved_transfers
        JOIN components ON components.id = unresolved_transfers.component_id
        WHERE components.name = ?
          AND unresolved_transfers.function_address = ?
          AND unresolved_transfers.function_instruction_set = ?
        ORDER BY source_address, instruction_set, control_flow, mnemonic, operands
        """,
        key,
    ).fetchall()
    failure_rows = connection.execute(
        """
        SELECT address
        FROM decode_failures
        JOIN components ON components.id = decode_failures.component_id
        WHERE components.name = ?
          AND decode_failures.function_address = ?
          AND decode_failures.function_instruction_set = ?
        ORDER BY address
        """,
        key,
    ).fetchall()
    try:
        edges = tuple(
            CFGEdge(
                source_address=int(row["source_address"]),
                source_instruction_address=int(row["source_instruction_address"]),
                target_address=int(row["target_address"]),
                target_instruction_set=InstructionSet(
                    str(row["target_instruction_set"])
                ),
                kind=CFGEdgeKind(str(row["kind"])),
            )
            for row in edge_rows
        )
        transfers = tuple(
            UnresolvedTransfer(
                source_address=int(row["source_address"]),
                instruction_set=InstructionSet(str(row["instruction_set"])),
                control_flow=ControlFlowKind(str(row["control_flow"])),
                mnemonic=str(row["mnemonic"]),
                operands=str(row["operands"]),
            )
            for row in transfer_rows
        )
    except ValueError as exc:
        raise AnalysisProjectError("persisted CFG record is invalid") from exc
    return FunctionControlFlowGraph(
        function=function,
        blocks=tuple(blocks),
        edges=edges,
        unresolved_transfers=transfers,
        decode_failures=tuple(int(row["address"]) for row in failure_rows),
    )
