from __future__ import annotations

from nds_disassembly_toolkit.analysis.decompiler.model import (
    DecompilerVariable,
    DecompilerVariableKind,
    SourceRef,
)
from nds_disassembly_toolkit.analysis.decompiler.prototype import (
    FunctionPrototype,
    PrototypeParameter,
    PrototypePropagationResult,
)
from nds_disassembly_toolkit.analysis.decompiler.prototype_service import (
    ProjectPrototypeAnalysis,
    build_project_render_type_context,
)
from nds_disassembly_toolkit.analysis.decompiler.ssa import (
    SSABlock,
    SSACallExpression,
    SSACallStatement,
    SSAFunction,
    SSAReferenceExpression,
    SSAReturnStatement,
    SSAStorage,
    SSAStorageKind,
    SSAValue,
)
from nds_disassembly_toolkit.analysis.decompiler.structure_recovery import (
    LocalStructureRecovery,
)
from nds_disassembly_toolkit.analysis.decompiler.type_model import (
    PointerType,
    VoidType,
)
from nds_disassembly_toolkit.analysis.decompiler.type_propagation import (
    FunctionTypeIdentity,
    LocalTypeEnvironment,
)
from nds_disassembly_toolkit.analysis.model import InstructionSet, Register

BASE = 0x0200D000
TARGET = BASE + 0x100


def _source(address: int) -> tuple[SourceRef, ...]:
    return (SourceRef(address, InstructionSet.ARM),)


def _reg(version: int, address: int) -> SSAValue:
    return SSAValue(
        SSAStorage(SSAStorageKind.REGISTER, register=Register.R0),
        version,
        _source(address),
    )


def _identity() -> FunctionTypeIdentity:
    return FunctionTypeIdentity(
        "arm9",
        BASE,
        InstructionSet.ARM,
    )


def _environment() -> LocalTypeEnvironment:
    return LocalTypeEnvironment(
        value_bindings=(),
        field_bindings=(),
        structures=LocalStructureRecovery(()),
    )


def _function() -> tuple[SSAFunction, SSAValue, SSAValue]:
    entry = _reg(0, BASE)
    result = _reg(1, BASE + 4)
    source = _source(BASE + 4)
    argument = DecompilerVariable(
        "arg0",
        DecompilerVariableKind.ARGUMENT,
        register=Register.R0,
    )
    function = SSAFunction(
        component="arm9",
        address=BASE,
        instruction_set=InstructionSet.ARM,
        name="caller",
        parameters=(argument,),
        locals=(),
        blocks=(
            SSABlock(
                BASE,
                InstructionSet.ARM,
                (),
                (
                    SSACallStatement(
                        SSACallExpression(
                            "find_actor",
                            TARGET,
                            InstructionSet.ARM,
                            "arm9",
                            (
                                SSAReferenceExpression(
                                    entry.storage,
                                    entry,
                                    source,
                                ),
                            ),
                            source,
                        ),
                        source,
                        result,
                    ),
                    SSAReturnStatement(
                        SSAReferenceExpression(
                            result.storage,
                            result,
                            _source(BASE + 8),
                        ),
                        _source(BASE + 8),
                    ),
                ),
                (),
            ),
        ),
        entry_definitions=(entry,),
    )
    return function, entry, result


def test_project_render_context_uses_propagated_signature_and_call_result_type() -> None:
    function, _, result = _function()
    identity = _identity()
    pointer = PointerType(
        pointee_name="struct_actor",
        component="arm9",
    )
    prototype = FunctionPrototype(
        identity=identity,
        name="caller",
        parameters=(
            PrototypeParameter(
                position=0,
                name="arg0",
                register=Register.R0,
                stack_offset=None,
                recovered_type=pointer,
            ),
        ),
        return_type=pointer,
    )
    propagation = PrototypePropagationResult(
        prototypes=(prototype,),
        value_types=((identity, result, pointer),),
        converged=True,
        iterations=2,
    )
    analysis = ProjectPrototypeAnalysis(
        propagation=propagation,
        functions=(function,),
        environments=(_environment(),),
    )

    context = build_project_render_type_context(
        analysis,
        identity,
    )

    assert context.parameter_types == (
        ("arg0", "struct struct_actor *"),
    )
    assert context.local_types == (
        ("call_result_0", "struct struct_actor *"),
    )
    assert context.return_type == "struct struct_actor *"
    assert context.forward_structs == ("struct_actor",)


def test_project_render_context_renders_proven_void_return() -> None:
    function, _, _ = _function()
    identity = _identity()
    prototype = FunctionPrototype(
        identity=identity,
        name="caller",
        parameters=(
            PrototypeParameter(
                position=0,
                name="arg0",
                register=Register.R0,
                stack_offset=None,
                recovered_type=PointerType(),
            ),
        ),
        return_type=VoidType(),
    )
    analysis = ProjectPrototypeAnalysis(
        propagation=PrototypePropagationResult(
            prototypes=(prototype,),
            value_types=(),
            converged=True,
            iterations=1,
        ),
        functions=(function,),
        environments=(_environment(),),
    )

    context = build_project_render_type_context(
        analysis,
        identity,
    )

    assert context.return_type == "void"


def test_missing_project_prototype_context_is_empty_and_safe() -> None:
    function, _, _ = _function()
    other = FunctionTypeIdentity(
        "overlay_0",
        BASE,
        InstructionSet.ARM,
    )
    analysis = ProjectPrototypeAnalysis(
        propagation=PrototypePropagationResult(
            prototypes=(),
            value_types=(),
            converged=True,
            iterations=1,
        ),
        functions=(function,),
        environments=(_environment(),),
    )

    context = build_project_render_type_context(
        analysis,
        other,
    )

    assert context.parameter_types == ()
    assert context.local_types == ()
    assert context.structures == ()
    assert context.forward_structs == ()
    assert context.return_type is None
