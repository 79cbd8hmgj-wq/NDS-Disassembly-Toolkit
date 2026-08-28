from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from hashlib import sha256

from nds_disassembly_toolkit.analysis.model import (
    Component,
    CrossReference,
    FunctionCandidate,
    FunctionControlFlowGraph,
    FunctionDataFlow,
    StringRecord,
    SymbolTable,
)

_U32_MAX = 0xFFFFFFFF


class AnalysisFreshness(StrEnum):
    CURRENT = "current"
    STALE = "stale"
    MISSING = "missing"


@dataclass(frozen=True)
class AnalysisProjectMetadata:
    project_format_version: int
    schema_version: int
    analysis_model_version: int
    read_only: bool

    def __post_init__(self) -> None:
        if self.project_format_version <= 0:
            raise ValueError("project format version must be positive")
        if self.schema_version <= 0:
            raise ValueError("schema version must be positive")
        if self.analysis_model_version <= 0:
            raise ValueError("analysis model version must be positive")


@dataclass(frozen=True)
class ComponentAnalysisIdentity:
    name: str
    base_address: int
    size: int
    sha256: str

    def __post_init__(self) -> None:
        if not self.name:
            raise ValueError("component name cannot be empty")
        if not 0 <= self.base_address <= _U32_MAX:
            raise ValueError("component base address must be an unsigned 32-bit value")
        if self.size < 0:
            raise ValueError("component size must be non-negative")
        if len(self.sha256) != 64 or self.sha256 != self.sha256.lower():
            raise ValueError("component sha256 must be 64 lowercase hexadecimal characters")
        try:
            int(self.sha256, 16)
        except ValueError as exc:
            raise ValueError(
                "component sha256 must be 64 lowercase hexadecimal characters"
            ) from exc

    @classmethod
    def from_component(cls, component: Component) -> ComponentAnalysisIdentity:
        return cls(
            name=component.name,
            base_address=component.base_address,
            size=len(component.data),
            sha256=sha256(component.data).hexdigest(),
        )


@dataclass(frozen=True)
class LocationAnnotation:
    component: str
    address: int
    name_override: str | None = None
    comment: str | None = None
    tags: tuple[str, ...] = ()
    bookmarked: bool = False

    def __post_init__(self) -> None:
        if not self.component:
            raise ValueError("annotation component cannot be empty")
        if not 0 <= self.address <= _U32_MAX:
            raise ValueError("annotation address must be an unsigned 32-bit value")
        if self.name_override == "":
            raise ValueError("annotation name override cannot be empty")
        if any(tag == "" for tag in self.tags):
            raise ValueError("annotation tags cannot be empty")
        object.__setattr__(self, "tags", tuple(sorted(set(self.tags))))


@dataclass(frozen=True)
class ComponentAnalysisBundle:
    component: Component
    functions: tuple[FunctionCandidate, ...] = ()
    cfgs: tuple[FunctionControlFlowGraph, ...] = ()
    xrefs: tuple[CrossReference, ...] = ()
    strings: tuple[StringRecord, ...] = ()
    symbols: SymbolTable = field(default_factory=lambda: SymbolTable(()))
    data_flows: tuple[FunctionDataFlow, ...] = ()

    def __post_init__(self) -> None:
        component_name = self.component.name
        if not component_name:
            raise ValueError("bundle component name cannot be empty")
        for function in self.functions:
            if function.component != component_name:
                raise ValueError("bundle function belongs to a different component")
        for cfg in self.cfgs:
            if cfg.function.component != component_name:
                raise ValueError("bundle CFG belongs to a different component")
        for reference in self.xrefs:
            if reference.source_component != component_name:
                raise ValueError("bundle xref belongs to a different component")
        for record in self.strings:
            if record.component != component_name:
                raise ValueError("bundle string belongs to a different component")
        for symbol in self.symbols.symbols:
            if symbol.component != component_name:
                raise ValueError("bundle symbol belongs to a different component")
        for flow in self.data_flows:
            if flow.function.component != component_name:
                raise ValueError("bundle data flow belongs to a different component")
