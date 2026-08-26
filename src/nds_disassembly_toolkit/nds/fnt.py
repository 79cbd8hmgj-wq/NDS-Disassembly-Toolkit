from __future__ import annotations

from dataclasses import dataclass
from pathlib import PurePosixPath

from nds_disassembly_toolkit.errors import RomFormatError
from nds_disassembly_toolkit.nds.header import NdsHeader
from nds_disassembly_toolkit.util import Buffer, read_u16_le, read_u32_le, require_range

ROOT_DIRECTORY_ID = 0xF000


@dataclass(frozen=True)
class FntDirectory:
    dir_id: int
    parent_id: int
    first_file_id: int
    path: str


@dataclass(frozen=True)
class FntFile:
    file_id: int
    path: str


@dataclass(frozen=True)
class FntTree:
    directories: tuple[FntDirectory, ...]
    files: tuple[FntFile, ...]

    def file_by_id(self) -> dict[int, FntFile]:
        return {entry.file_id: entry for entry in self.files}


@dataclass(frozen=True)
class _DirectoryRecord:
    subtable_offset: int
    first_file_id: int
    parent_id: int


def _directory_index(dir_id: int, directory_count: int) -> int:
    if dir_id < ROOT_DIRECTORY_ID:
        raise RomFormatError(f"invalid FNT directory ID 0x{dir_id:04X}")
    index = dir_id - ROOT_DIRECTORY_ID
    if index >= directory_count:
        raise RomFormatError(
            f"FNT directory ID 0x{dir_id:04X} resolves to index {index}, "
            f"but only {directory_count} directories exist"
        )
    return index


def _join(parent: str, name: str) -> str:
    return str(PurePosixPath(parent, name)) if parent else name


def parse_fnt(data: Buffer, header: NdsHeader, fat_entry_count: int) -> FntTree:
    table = require_range(data, header.fnt_offset, header.fnt_size, "FNT")
    if len(table) < 8:
        raise RomFormatError("FNT is too small for the root directory record")

    directory_count = read_u16_le(table, 6, "FNT root directory count")
    if directory_count == 0:
        raise RomFormatError("FNT declares zero directories")
    require_range(table, 0, directory_count * 8, "FNT directory table")

    records = tuple(
        _DirectoryRecord(
            subtable_offset=read_u32_le(table, index * 8, f"FNT directory {index} subtable"),
            first_file_id=read_u16_le(table, index * 8 + 4, f"FNT directory {index} file ID"),
            parent_id=read_u16_le(table, index * 8 + 6, f"FNT directory {index} parent"),
        )
        for index in range(directory_count)
    )

    directories: list[FntDirectory] = []
    files: list[FntFile] = []
    visited: set[int] = set()

    def walk(dir_id: int, path: str) -> None:
        index = _directory_index(dir_id, directory_count)
        if dir_id in visited:
            raise RomFormatError(f"FNT directory cycle detected at 0x{dir_id:04X}")
        visited.add(dir_id)
        record = records[index]
        directories.append(
            FntDirectory(
                dir_id=dir_id,
                parent_id=record.parent_id,
                first_file_id=record.first_file_id,
                path=path,
            )
        )
        cursor = record.subtable_offset
        file_id = record.first_file_id
        while True:
            entry_type = require_range(
                table, cursor, 1, f"FNT directory 0x{dir_id:04X} entry"
            )[0]
            cursor += 1
            if entry_type == 0:
                return
            name_length = entry_type & 0x7F
            if name_length == 0:
                raise RomFormatError(f"FNT directory 0x{dir_id:04X} has an empty name")
            name_bytes = require_range(table, cursor, name_length, "FNT entry name").tobytes()
            cursor += name_length
            try:
                name = name_bytes.decode("ascii")
            except UnicodeDecodeError as exc:
                raise RomFormatError(f"FNT name is not ASCII: {name_bytes!r}") from exc
            child_path = _join(path, name)
            if entry_type & 0x80:
                child_id = read_u16_le(table, cursor, "FNT child directory ID")
                cursor += 2
                _directory_index(child_id, directory_count)
                walk(child_id, child_path)
            else:
                if file_id >= fat_entry_count:
                    raise RomFormatError(
                        f"FNT references file ID {file_id}, but FAT contains only "
                        f"{fat_entry_count} entries"
                    )
                files.append(FntFile(file_id=file_id, path=child_path))
                file_id += 1

    walk(ROOT_DIRECTORY_ID, "")
    if len(visited) != directory_count:
        visited_indexes = {item - ROOT_DIRECTORY_ID for item in visited}
        missing = sorted(set(range(directory_count)) - visited_indexes)
        raise RomFormatError(f"FNT contains unreachable directory indexes: {missing}")
    return FntTree(
        directories=tuple(sorted(directories, key=lambda item: item.dir_id)),
        files=tuple(sorted(files, key=lambda item: item.file_id)),
    )
