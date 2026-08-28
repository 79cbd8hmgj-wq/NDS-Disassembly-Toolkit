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
