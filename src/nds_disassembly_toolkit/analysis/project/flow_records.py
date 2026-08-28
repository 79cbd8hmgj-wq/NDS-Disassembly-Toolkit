from __future__ import annotations

import json
import sqlite3

from nds_disassembly_toolkit.analysis.model import (
    AbstractValue,
    AbstractValueKind,
    ArgumentEvidence,
    ArgumentLocationKind,
    BlockFlowState,
    FunctionCandidate,
    FunctionControlFlowGraph,
    FunctionDataFlow,
    FunctionSummary,
    InstructionFlowState,
    Register,
    RegisterState,
    ReturnEvidence,
    StackAccess,
    StackAccessKind,
    StackFrame,
    StackSlot,
    StackSlotKind,
    StackState,
)
from nds_disassembly_toolkit.analysis.project.codec import dump_int_tuple, load_int_tuple
from nds_disassembly_toolkit.analysis.project.model import ComponentAnalysisBundle
from nds_disassembly_toolkit.errors import AnalysisProjectError


def _dump_stack_state(state: StackState | None) -> str | None:
    if state is None:
        return None
    payload = {
        "frame_pointers": [
            [register.value, offset] for register, offset in state.frame_pointers
        ],
        "offset": state.offset,
    }
    return json.dumps(payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def _load_stack_state(value: object) -> StackState | None:
    if value is None:
        return None
    try:
        decoded = json.loads(str(value))
        if not isinstance(decoded, dict):
            raise ValueError("stack state is not an object")
        offset_value = decoded["offset"]
        frame_pointers = decoded["frame_pointers"]
        if not isinstance(frame_pointers, list):
            raise ValueError("frame pointers are invalid")
        pairs: list[tuple[Register, int]] = []
        for pair in frame_pointers:
            if not isinstance(pair, list) or len(pair) != 2:
                raise ValueError("frame pointer entry is invalid")
            pairs.append((Register(str(pair[0])), int(pair[1])))
        return StackState(
            None if offset_value is None else int(offset_value),
            tuple(pairs),
        )
    except (json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
        raise AnalysisProjectError("persisted stack state is invalid") from exc


def _value_fields(value: AbstractValue) -> tuple[str, int | None, str | None, str]:
    return (
        value.kind.value,
        value.value,
        value.component,
        dump_int_tuple(value.provenance),
    )


def _optional_int(value: object) -> int | None:
    if value is None:
        return None
    if not isinstance(value, int) or isinstance(value, bool):
        raise AnalysisProjectError("persisted integer value is invalid")
    return value


def _value_from_fields(
    kind: object,
    value: object,
    owner_component: object,
    provenance_json: object,
) -> AbstractValue:
    try:
        return AbstractValue(
            kind=AbstractValueKind(str(kind)),
            value=_optional_int(value),
            component=None if owner_component is None else str(owner_component),
            provenance=load_int_tuple(str(provenance_json)),
        )
    except ValueError as exc:
        raise AnalysisProjectError("persisted abstract value is invalid") from exc


def validate_data_flow_bundle(bundle: ComponentAnalysisBundle) -> None:
    function_keys = {
        (function.address, function.instruction_set): function for function in bundle.functions
    }
    cfgs = {
        (cfg.function.address, cfg.function.instruction_set): cfg for cfg in bundle.cfgs
    }
    for flow in bundle.data_flows:
        key = (flow.function.address, flow.function.instruction_set)
        if function_keys.get(key) != flow.function:
            raise AnalysisProjectError(
                "bundle data-flow function is not present in bundle functions"
            )
        cfg = cfgs.get(key)
        if cfg is None or cfg.function != flow.function:
            raise AnalysisProjectError("bundle data flow has no matching CFG")
        block_keys = {(block.address, block.instruction_set) for block in cfg.blocks}
        instruction_by_address = {
            instruction.address: instruction
            for block in cfg.blocks
            for instruction in block.instructions
        }
        for block in flow.blocks:
            if (block.address, block.instruction_set) not in block_keys:
                raise AnalysisProjectError("bundle data-flow block is not present in CFG")
        for state in flow.instructions:
            instruction = instruction_by_address.get(state.address)
            if instruction is None:
                raise AnalysisProjectError(
                    "bundle data-flow instruction is not present in CFG"
                )
            if instruction != state.instruction:
                raise AnalysisProjectError(
                    "bundle data-flow instruction does not match CFG instruction"
                )


def delete_data_flows(connection: sqlite3.Connection, component_id_value: int) -> None:
    for table in (
        "return_evidence",
        "argument_uses",
        "argument_evidence",
        "stack_accesses",
        "stack_slots",
        "stack_frames",
        "function_warnings",
        "register_flow",
        "instruction_flow",
        "block_flow",
    ):
        connection.execute(
            f"DELETE FROM {table} WHERE component_id = ?",
            (component_id_value,),
        )


def _insert_register_state(
    connection: sqlite3.Connection,
    key: tuple[int, int, str],
    scope_kind: str,
    scope_address: int,
    scope_side: str,
    state: RegisterState,
) -> None:
    connection.executemany(
        """
        INSERT INTO register_flow(
            component_id,
            function_address,
            function_instruction_set,
            scope_kind,
            scope_address,
            scope_side,
            register,
            value_kind,
            value,
            owner_component,
            provenance_json
        ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        tuple(
            (
                *key,
                scope_kind,
                scope_address,
                scope_side,
                register.value,
                *_value_fields(value),
            )
            for register, value in state.values
        ),
    )


def _insert_summary(
    connection: sqlite3.Connection,
    key: tuple[int, int, str],
    summary: FunctionSummary,
) -> None:
    connection.execute(
        """
        INSERT INTO stack_frames(
            component_id,
            function_address,
            function_instruction_set,
            frame_size,
            frame_pointer,
            stack_depth_known
        ) VALUES(?, ?, ?, ?, ?, ?)
        """,
        (
            *key,
            summary.stack_frame.frame_size,
            (
                None
                if summary.stack_frame.frame_pointer is None
                else summary.stack_frame.frame_pointer.value
            ),
            int(summary.stack_frame.stack_depth_known),
        ),
    )
    for slot in summary.stack_slots:
        connection.execute(
            """
            INSERT INTO stack_slots(
                component_id,
                function_address,
                function_instruction_set,
                slot_offset,
                kind
            ) VALUES(?, ?, ?, ?, ?)
            """,
            (*key, slot.offset, slot.kind.value),
        )
        for ordinal, access in enumerate(slot.accesses):
            connection.execute(
                """
                INSERT INTO stack_accesses(
                    component_id,
                    function_address,
                    function_instruction_set,
                    slot_offset,
                    ordinal,
                    instruction_address,
                    kind,
                    width
                ) VALUES(?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    *key,
                    slot.offset,
                    ordinal,
                    access.instruction_address,
                    access.kind.value,
                    access.width,
                ),
            )
    for ordinal, argument in enumerate(summary.arguments):
        connection.execute(
            """
            INSERT INTO argument_evidence(
                component_id,
                function_address,
                function_instruction_set,
                ordinal,
                arg_index,
                kind,
                register,
                stack_offset
            ) VALUES(?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                *key,
                ordinal,
                argument.index,
                argument.kind.value,
                None if argument.register is None else argument.register.value,
                argument.stack_offset,
            ),
        )
        for use_ordinal, address in enumerate(argument.uses):
            connection.execute(
                """
                INSERT INTO argument_uses(
                    component_id,
                    function_address,
                    function_instruction_set,
                    argument_ordinal,
                    ordinal,
                    instruction_address
                ) VALUES(?, ?, ?, ?, ?, ?)
                """,
                (*key, ordinal, use_ordinal, address),
            )
    for ordinal, evidence in enumerate(summary.returns):
        connection.execute(
            """
            INSERT INTO return_evidence(
                component_id,
                function_address,
                function_instruction_set,
                ordinal,
                return_address,
                value_kind,
                value,
                owner_component,
                provenance_json
            ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                *key,
                ordinal,
                evidence.return_address,
                *_value_fields(evidence.value),
            ),
        )


def insert_data_flows(
    connection: sqlite3.Connection,
    component_id_value: int,
    flows: tuple[FunctionDataFlow, ...],
) -> None:
    for flow in flows:
        key = (
            component_id_value,
            flow.function.address,
            flow.function.instruction_set.value,
        )
        for block in flow.blocks:
            connection.execute(
                """
                INSERT INTO block_flow(
                    component_id,
                    function_address,
                    function_instruction_set,
                    block_address,
                    block_instruction_set,
                    stack_entry_json,
                    stack_exit_json
                ) VALUES(?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    *key,
                    block.address,
                    block.instruction_set.value,
                    _dump_stack_state(block.stack_entry),
                    _dump_stack_state(block.stack_exit),
                ),
            )
            _insert_register_state(
                connection,
                key,
                "block",
                block.address,
                "entry",
                block.entry,
            )
            _insert_register_state(
                connection,
                key,
                "block",
                block.address,
                "exit",
                block.exit,
            )
        for state in flow.instructions:
            connection.execute(
                """
                INSERT INTO instruction_flow(
                    component_id,
                    function_address,
                    function_instruction_set,
                    instruction_address,
                    stack_before_json,
                    stack_after_json
                ) VALUES(?, ?, ?, ?, ?, ?)
                """,
                (
                    *key,
                    state.address,
                    _dump_stack_state(state.stack_before),
                    _dump_stack_state(state.stack_after),
                ),
            )
            _insert_register_state(
                connection,
                key,
                "instruction",
                state.address,
                "before",
                state.before,
            )
            _insert_register_state(
                connection,
                key,
                "instruction",
                state.address,
                "after",
                state.after,
            )
        connection.executemany(
            """
            INSERT INTO function_warnings(
                component_id,
                function_address,
                function_instruction_set,
                ordinal,
                text
            ) VALUES(?, ?, ?, ?, ?)
            """,
            tuple((*key, ordinal, warning) for ordinal, warning in enumerate(flow.warnings)),
        )
        if flow.summary is not None:
            _insert_summary(connection, key, flow.summary)


def _register_state(
    connection: sqlite3.Connection,
    component_id_value: int,
    function: FunctionCandidate,
    scope_kind: str,
    scope_address: int,
    scope_side: str,
) -> RegisterState:
    rows = connection.execute(
        """
        SELECT register, value_kind, value, owner_component, provenance_json
        FROM register_flow
        WHERE component_id = ?
          AND function_address = ?
          AND function_instruction_set = ?
          AND scope_kind = ?
          AND scope_address = ?
          AND scope_side = ?
        ORDER BY register
        """,
        (
            component_id_value,
            function.address,
            function.instruction_set.value,
            scope_kind,
            scope_address,
            scope_side,
        ),
    ).fetchall()
    try:
        return RegisterState(
            tuple(
                (
                    Register(str(row["register"])),
                    _value_from_fields(
                        row["value_kind"],
                        row["value"],
                        row["owner_component"],
                        row["provenance_json"],
                    ),
                )
                for row in rows
            )
        )
    except ValueError as exc:
        raise AnalysisProjectError("persisted register flow is invalid") from exc


def _summary_from_database(
    connection: sqlite3.Connection,
    component_id_value: int,
    function: FunctionCandidate,
) -> FunctionSummary | None:
    key = (component_id_value, function.address, function.instruction_set.value)
    frame_row = connection.execute(
        """
        SELECT frame_size, frame_pointer, stack_depth_known
        FROM stack_frames
        WHERE component_id = ? AND function_address = ? AND function_instruction_set = ?
        """,
        key,
    ).fetchone()
    if frame_row is None:
        return None
    try:
        frame = StackFrame(
            frame_size=(
                None if frame_row["frame_size"] is None else int(frame_row["frame_size"])
            ),
            frame_pointer=(
                None
                if frame_row["frame_pointer"] is None
                else Register(str(frame_row["frame_pointer"]))
            ),
            stack_depth_known=bool(frame_row["stack_depth_known"]),
        )
    except ValueError as exc:
        raise AnalysisProjectError("persisted stack frame is invalid") from exc

    slot_rows = connection.execute(
        """
        SELECT slot_offset, kind
        FROM stack_slots
        WHERE component_id = ? AND function_address = ? AND function_instruction_set = ?
        ORDER BY slot_offset
        """,
        key,
    ).fetchall()
    slots: list[StackSlot] = []
    for slot_row in slot_rows:
        offset = int(slot_row["slot_offset"])
        access_rows = connection.execute(
            """
            SELECT instruction_address, kind, width
            FROM stack_accesses
            WHERE component_id = ?
              AND function_address = ?
              AND function_instruction_set = ?
              AND slot_offset = ?
            ORDER BY ordinal
            """,
            (*key, offset),
        ).fetchall()
        try:
            slots.append(
                StackSlot(
                    offset=offset,
                    kind=StackSlotKind(str(slot_row["kind"])),
                    accesses=tuple(
                        StackAccess(
                            instruction_address=int(row["instruction_address"]),
                            kind=StackAccessKind(str(row["kind"])),
                            width=int(row["width"]),
                        )
                        for row in access_rows
                    ),
                )
            )
        except ValueError as exc:
            raise AnalysisProjectError("persisted stack slot is invalid") from exc

    argument_rows = connection.execute(
        """
        SELECT ordinal, arg_index, kind, register, stack_offset
        FROM argument_evidence
        WHERE component_id = ? AND function_address = ? AND function_instruction_set = ?
        ORDER BY ordinal
        """,
        key,
    ).fetchall()
    arguments: list[ArgumentEvidence] = []
    for row in argument_rows:
        use_rows = connection.execute(
            """
            SELECT instruction_address
            FROM argument_uses
            WHERE component_id = ?
              AND function_address = ?
              AND function_instruction_set = ?
              AND argument_ordinal = ?
            ORDER BY ordinal
            """,
            (*key, int(row["ordinal"])),
        ).fetchall()
        try:
            arguments.append(
                ArgumentEvidence(
                    index=None if row["arg_index"] is None else int(row["arg_index"]),
                    kind=ArgumentLocationKind(str(row["kind"])),
                    register=(
                        None if row["register"] is None else Register(str(row["register"]))
                    ),
                    stack_offset=(
                        None if row["stack_offset"] is None else int(row["stack_offset"])
                    ),
                    uses=tuple(int(use["instruction_address"]) for use in use_rows),
                )
            )
        except ValueError as exc:
            raise AnalysisProjectError("persisted argument evidence is invalid") from exc

    return_rows = connection.execute(
        """
        SELECT return_address, value_kind, value, owner_component, provenance_json
        FROM return_evidence
        WHERE component_id = ? AND function_address = ? AND function_instruction_set = ?
        ORDER BY ordinal
        """,
        key,
    ).fetchall()
    returns = tuple(
        ReturnEvidence(
            return_address=int(row["return_address"]),
            value=_value_from_fields(
                row["value_kind"],
                row["value"],
                row["owner_component"],
                row["provenance_json"],
            ),
        )
        for row in return_rows
    )
    return FunctionSummary(tuple(arguments), returns, frame, tuple(slots))


def data_flow_from_database(
    connection: sqlite3.Connection,
    function: FunctionCandidate,
    cfg: FunctionControlFlowGraph,
) -> FunctionDataFlow | None:
    component_row = connection.execute(
        "SELECT id FROM components WHERE name = ?",
        (function.component,),
    ).fetchone()
    if component_row is None:
        return None
    component_id_value = int(component_row["id"])
    key = (component_id_value, function.address, function.instruction_set.value)
    block_rows = connection.execute(
        """
        SELECT block_address, block_instruction_set, stack_entry_json, stack_exit_json
        FROM block_flow
        WHERE component_id = ? AND function_address = ? AND function_instruction_set = ?
        """,
        key,
    ).fetchall()
    instruction_rows = connection.execute(
        """
        SELECT instruction_address, stack_before_json, stack_after_json
        FROM instruction_flow
        WHERE component_id = ? AND function_address = ? AND function_instruction_set = ?
        """,
        key,
    ).fetchall()
    warning_rows = connection.execute(
        """
        SELECT text
        FROM function_warnings
        WHERE component_id = ? AND function_address = ? AND function_instruction_set = ?
        ORDER BY ordinal
        """,
        key,
    ).fetchall()
    summary = _summary_from_database(connection, component_id_value, function)
    if not block_rows and not instruction_rows and not warning_rows and summary is None:
        return None

    block_map = {
        (int(row["block_address"]), str(row["block_instruction_set"])): row
        for row in block_rows
    }
    blocks: list[BlockFlowState] = []
    for block in cfg.blocks:
        row = block_map.get((block.address, block.instruction_set.value))
        if row is None:
            continue
        blocks.append(
            BlockFlowState(
                address=block.address,
                instruction_set=block.instruction_set,
                entry=_register_state(
                    connection,
                    component_id_value,
                    function,
                    "block",
                    block.address,
                    "entry",
                ),
                exit=_register_state(
                    connection,
                    component_id_value,
                    function,
                    "block",
                    block.address,
                    "exit",
                ),
                stack_entry=_load_stack_state(row["stack_entry_json"]),
                stack_exit=_load_stack_state(row["stack_exit_json"]),
            )
        )

    row_by_instruction = {
        int(row["instruction_address"]): row for row in instruction_rows
    }
    instructions: list[InstructionFlowState] = []
    for block in cfg.blocks:
        for instruction in block.instructions:
            row = row_by_instruction.get(instruction.address)
            if row is None:
                continue
            instructions.append(
                InstructionFlowState(
                    instruction=instruction,
                    before=_register_state(
                        connection,
                        component_id_value,
                        function,
                        "instruction",
                        instruction.address,
                        "before",
                    ),
                    after=_register_state(
                        connection,
                        component_id_value,
                        function,
                        "instruction",
                        instruction.address,
                        "after",
                    ),
                    stack_before=_load_stack_state(row["stack_before_json"]),
                    stack_after=_load_stack_state(row["stack_after_json"]),
                )
            )

    return FunctionDataFlow(
        function=function,
        blocks=tuple(blocks),
        instructions=tuple(instructions),
        warnings=tuple(str(row["text"]) for row in warning_rows),
        summary=summary,
    )
