from __future__ import annotations

from pathlib import Path

from nds_disassembly_toolkit.analysis.model import (
    Component,
    CrossReference,
    CrossReferenceKind,
    FunctionCandidate,
    InstructionSet,
    StringRecord,
    Symbol,
    SymbolKind,
    SymbolTable,
)
from nds_disassembly_toolkit.analysis.project import (
    AnalysisProject,
    ComponentAnalysisBundle,
)

BASE = 0x02000000


def _component(name: str = "arm9", *, base: int = BASE) -> Component:
    return Component(name, Path(f"{name}.bin"), base, bytes(0x100))


def _function(mode: InstructionSet, *, confidence: str = "high") -> FunctionCandidate:
    return FunctionCandidate(
        component="arm9",
        address=BASE + 0x20,
        offset=0x20,
        instruction_set=mode,
        confidence=confidence,
        evidence=("seed", "call"),
    )


def test_functions_round_trip_and_keep_arm_thumb_identity(tmp_path: Path) -> None:
    arm = _function(InstructionSet.ARM)
    thumb = _function(InstructionSet.THUMB, confidence="medium")
    root = tmp_path / "game.ndsre"

    with AnalysisProject.create(root) as project:
        project.store_component_analysis(
            ComponentAnalysisBundle(_component(), functions=(thumb, arm))
        )

    with AnalysisProject.open(root, read_only=True) as project:
        assert project.functions(component="arm9") == (arm, thumb)
        assert project.function("arm9", BASE + 0x20, InstructionSet.ARM) == arm
        assert project.function("arm9", BASE + 0x20, InstructionSet.THUMB) == thumb


def test_strings_symbols_and_xrefs_round_trip(tmp_path: Path) -> None:
    function = _function(InstructionSet.ARM)
    string = StringRecord("arm9", 0x40, BASE + 0x40, "hello")
    symbols = SymbolTable(
        (
            Symbol(
                component="arm9",
                address=BASE + 0x40,
                offset=0x40,
                name="message",
                kind=SymbolKind.STRING,
                instruction_set=None,
                confidence="high",
                evidence=("explicit", "string"),
            ),
            Symbol(
                component="arm9",
                address=BASE + 0x20,
                offset=0x20,
                name="entry",
                kind=SymbolKind.FUNCTION,
                instruction_set=InstructionSet.ARM,
                confidence="high",
                evidence=("function",),
            ),
        )
    )
    call = CrossReference(
        kind=CrossReferenceKind.CALL,
        source_component="arm9",
        source_address=BASE + 0x24,
        source_function_address=BASE + 0x20,
        source_instruction_set=InstructionSet.ARM,
        target_address=0x02200000,
        target_instruction_set=InstructionSet.THUMB,
    )
    pointer = CrossReference(
        kind=CrossReferenceKind.DATA_POINTER,
        source_component="arm9",
        source_address=BASE + 0x48,
        source_function_address=None,
        source_instruction_set=None,
        target_address=0x02200000,
        target_instruction_set=None,
    )
    root = tmp_path / "game.ndsre"

    with AnalysisProject.create(root) as project:
        project.store_component_analysis(
            ComponentAnalysisBundle(
                _component(),
                functions=(function,),
                strings=(string,),
                symbols=symbols,
                xrefs=(pointer, call),
            )
        )

    with AnalysisProject.open(root, read_only=True) as project:
        assert project.string_at("arm9", BASE + 0x40) == string
        assert project.strings(component="arm9") == (string,)
        assert project.symbols_at("arm9", BASE + 0x20) == (symbols.symbols[1],)
        assert project.symbols_named("message") == (symbols.symbols[0],)
        assert project.xrefs_from("arm9", BASE + 0x24) == (call,)
        assert project.xrefs_to(0x02200000) == (call, pointer)


def test_same_address_symbols_in_overlays_stay_independent(tmp_path: Path) -> None:
    address = 0x02200000
    symbol_3 = Symbol(
        "overlay_3",
        address,
        0,
        "shared_address",
        SymbolKind.DATA,
        None,
        "high",
        ("overlay3",),
    )
    symbol_7 = Symbol(
        "overlay_7",
        address,
        0,
        "shared_address",
        SymbolKind.DATA,
        None,
        "medium",
        ("overlay7",),
    )
    root = tmp_path / "game.ndsre"

    with AnalysisProject.create(root) as project:
        project.store_component_analysis(
            ComponentAnalysisBundle(
                _component("overlay_7", base=address),
                symbols=SymbolTable((symbol_7,)),
            )
        )
        project.store_component_analysis(
            ComponentAnalysisBundle(
                _component("overlay_3", base=address),
                symbols=SymbolTable((symbol_3,)),
            )
        )

        assert project.symbols_named("shared_address") == (symbol_3, symbol_7)
        assert project.symbols_at("overlay_3", address) == (symbol_3,)
        assert project.symbols_at("overlay_7", address) == (symbol_7,)
