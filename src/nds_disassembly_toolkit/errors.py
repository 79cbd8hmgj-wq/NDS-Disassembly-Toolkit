class NdsToolkitError(Exception):
    """Base exception for expected toolkit failures."""


class ProfileError(NdsToolkitError):
    """Raised when a ROM profile is malformed or incomplete."""


class UnsupportedRomError(NdsToolkitError):
    """Raised when a ROM does not match a selected supported profile."""


class RomFormatError(NdsToolkitError):
    """Raised when Nintendo DS structures are malformed."""


class BoundsError(RomFormatError):
    """Raised when a structure points outside the available ROM bytes."""


class WorkspaceError(NdsToolkitError):
    """Raised when a workspace cannot be safely created or replaced."""


class DisassemblyError(NdsToolkitError):
    """Raised when executable/disassembly operations cannot be completed safely."""


class AnalysisProjectError(NdsToolkitError):
    """Raised when a persistent analysis project cannot be used safely."""


class InvestigationError(AnalysisProjectError):
    """Raised when an investigation request cannot be evaluated safely."""


class DecompilerError(NdsToolkitError):
    """Raised when conservative decompilation cannot be completed safely."""


class RuntimeAnalysisError(NdsToolkitError):
    """Raised when a runtime-analysis operation cannot be completed safely."""


class RuntimeConnectionError(RuntimeAnalysisError):
    """Raised when a runtime debugger endpoint cannot be reached."""


class RuntimeProtocolError(RuntimeAnalysisError):
    """Raised when a runtime debugger peer violates the expected protocol."""


class RuntimeTimeoutError(RuntimeAnalysisError):
    """Raised when a runtime debugger operation times out."""


class RuntimeTargetStateError(RuntimeAnalysisError):
    """Raised when the target state is unsuitable for a requested operation."""


class RuntimeTraceError(RuntimeAnalysisError):
    """Raised when persisted runtime trace work cannot complete safely."""


class RuntimeTraceFormatError(RuntimeTraceError):
    """Raised when a .ndstrace file violates its persisted format contract."""


class RuntimeTraceMismatchError(RuntimeTraceError):
    """Raised when two known trace targets cannot be compared safely."""
