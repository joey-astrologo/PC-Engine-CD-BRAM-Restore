#!/usr/bin/env python3
"""Inspect raw PC Engine BRAM and cautiously repair supported structural damage."""

import argparse
from dataclasses import dataclass, field
import hashlib
import os
from pathlib import Path
import stat
import struct
import sys
from typing import List, Optional, Tuple


BANK_SIZE = 2048
BASE_ADDRESS = 0x8000
HEADER_SIZE = 16
PROFILE = "rondo-known-repair"
GENERIC_PROFILE = "generic-structural"
ORIGINAL_SHA256 = "b94b49830c46d36598bd43a186628a7189c114d1b1785a4f877fb9f1dfaca3f4"
REPAIRED_SHA256 = "30cf675f6d75fd6f178acce3ae63e32145b1e1352d41af8262d51a1a246454d4"
RONDO_PATCH = ((0x05, 0x08, 0x88), (0x06, 0x10, 0xB0), (0x10, 0x00, 0xA0))


class BramError(Exception):
    """An unsupported file or a refused/unsuccessful operation."""


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def require_size(size: int) -> None:
    if size != BANK_SIZE:
        raise BramError(
            f"Unsupported size: {size} bytes; expected exactly {BANK_SIZE} bytes "
            "(one raw BRAM bank)."
        )


def u16(data: bytes, offset: int) -> int:
    return struct.unpack_from("<H", data, offset)[0]


@dataclass(frozen=True)
class Entry:
    offset: int
    length: int
    stored_checksum: Optional[int]
    identifier: bytes
    filename: bytes
    byte_sum: Optional[int]

    @property
    def expected_checksum(self) -> Optional[int]:
        return None if self.byte_sum is None else (-self.byte_sum) & 0xFFFF

    @property
    def checksum_valid(self) -> bool:
        return self.byte_sum is not None and self.stored_checksum == self.expected_checksum


@dataclass
class Inspection:
    signature: bytes
    memory_end: int
    free_address: int
    reserved: bytes
    entries: List[Entry] = field(default_factory=list)
    header_errors: List[str] = field(default_factory=list)
    directory_errors: List[str] = field(default_factory=list)
    checksum_errors: List[str] = field(default_factory=list)
    terminator: Optional[int] = None
    residual_nonzero_bytes: int = 0

    @property
    def free_offset(self) -> int:
        return self.free_address - BASE_ADDRESS

    @property
    def structural_valid(self) -> bool:
        return not self.header_errors and not self.directory_errors

    @property
    def valid(self) -> bool:
        return self.structural_valid and all(e.checksum_valid for e in self.entries)


def inspect_bytes(data: bytes) -> Inspection:
    """Walk the directory using physical bounds, independently of any recovery profile.

    A broken free pointer must not hide entries. Nonzero residual bytes after a
    terminator are legal and do not establish that another entry is live.
    """
    require_size(len(data))
    report = Inspection(data[:4], u16(data, 4), u16(data, 6), data[8:16])
    if report.signature != b"HUBM":
        report.header_errors.append(f"Invalid signature {report.signature!r}; expected b'HUBM'.")
    if report.memory_end != BASE_ADDRESS + BANK_SIZE:
        report.header_errors.append(
            f"Memory boundary is 0x{report.memory_end:04X}; expected 0x8800 for a 2048-byte bank."
        )
    if not HEADER_SIZE <= report.free_offset <= BANK_SIZE - 2:
        report.header_errors.append(
            f"Free-space pointer 0x{report.free_address:04X} is out of bounds: "
            "it must address two bytes in offsets [0x0010, 0x07FE]."
        )
    elif u16(data, report.free_offset) != 0:
        report.directory_errors.append(
            f"Free-space pointer at offset 0x{report.free_offset:04X} does not point to a zero length."
        )

    offset = HEADER_SIZE
    while True:
        if offset + 2 > BANK_SIZE:
            report.directory_errors.append(
                f"Missing/truncated directory terminator at 0x{offset:04X}; "
                "two zero bytes are required within the bank."
            )
            break
        length = u16(data, offset)
        if length == 0:
            report.terminator = offset
            report.residual_nonzero_bytes = sum(b != 0 for b in data[offset + 2:])
            break

        complete_header = offset + HEADER_SIZE <= BANK_SIZE
        complete_entry = complete_header and HEADER_SIZE <= length <= BANK_SIZE - offset
        entry = Entry(
            offset, length,
            u16(data, offset + 2) if offset + 4 <= BANK_SIZE else None,
            data[offset + 4:offset + 6], data[offset + 6:offset + 16],
            sum(data[offset + 4:offset + length]) if complete_entry else None,
        )
        report.entries.append(entry)
        if length < HEADER_SIZE:
            report.directory_errors.append(
                f"Entry at 0x{offset:04X} has length {length}, smaller than its 16-byte header."
            )
        if not complete_header:
            report.directory_errors.append(f"Truncated entry header at 0x{offset:04X}.")
        if offset + length > BANK_SIZE:
            report.directory_errors.append(
                f"Entry at 0x{offset:04X} ends at 0x{offset + length:04X}, "
                "out of bounds beyond 0x0800 (truncated entry)."
            )
        if not complete_entry:
            break
        if not entry.checksum_valid:
            report.checksum_errors.append(f"Checksum mismatch in entry at 0x{offset:04X}.")
        offset += length

    if report.terminator is None:
        report.directory_errors.append("Directory/free-space pointer agreement cannot be established.")
    elif report.free_offset != report.terminator:
        report.directory_errors.append(
            f"Directory terminator at 0x{report.terminator:04X} disagrees with "
            f"free-space pointer offset {report.free_offset:#06x}."
        )
    return report


def print_inspection(report: Inspection) -> None:
    print(f"Bank header: {'PASS' if not report.header_errors else 'FAIL'}")
    print(f"  Signature: {report.signature!r}")
    print(f"  Memory boundary: 0x{report.memory_end:04X} (expected 0x8800)")
    print(f"  Next free: 0x{report.free_address:04X} -> file offset {report.free_offset:#06x}")
    print(f"  Reserved bytes: {report.reserved.hex(' ').upper()}")
    print(f"Directory entries: {len(report.entries)}")
    for index, entry in enumerate(report.entries, 1):
        print(f"  Entry {index} at 0x{entry.offset:04X}: length 0x{entry.length:04X} ({entry.length})")
        print(f"    Identifier bytes: {entry.identifier.hex(' ').upper()}")
        print(f"    Filename bytes: {entry.filename.hex(' ').upper()} ({entry.filename!r})")
        if entry.byte_sum is None:
            stored = "unavailable" if entry.stored_checksum is None else f"0x{entry.stored_checksum:04X}"
            print(f"    Checksum: NOT CHECKED (invalid bounds/length); stored={stored}")
        else:
            print(
                f"    Payload: [0x{entry.offset + HEADER_SIZE:04X}, "
                f"0x{entry.offset + entry.length:04X}), {entry.length - HEADER_SIZE} bytes"
            )
            print(
                f"    Checksum: {'PASS' if entry.checksum_valid else 'FAIL'}; "
                f"stored=0x{entry.stored_checksum:04X}, expected=0x{entry.expected_checksum:04X}, "
                f"byte sum={entry.byte_sum}"
            )
    if report.terminator is not None:
        print(f"Directory terminator: 0x{report.terminator:04X} (00 00)")
        print(f"Directory/free-space pointer: {'PASS' if report.terminator == report.free_offset else 'FAIL'}")
        print(f"Residual nonzero bytes after terminator: {report.residual_nonzero_bytes} (outside declared directory)")
    else:
        print("Directory terminator: NOT FOUND; directory/free-space pointer: UNVERIFIED")
    for error in report.header_errors + report.directory_errors + report.checksum_errors:
        print(f"ERROR: {error}")
    print(f"Structural validation: {'PASS' if report.structural_valid else 'FAIL'}")
    if report.checksum_errors:
        checksum_status = "FAIL"
    elif report.terminator is None or any(e.byte_sum is None for e in report.entries):
        checksum_status = "INCOMPLETE"
    else:
        checksum_status = f"PASS ({len(report.entries)} entries checked)"
    print(f"Checksum validation: {checksum_status}")
    print(f"Overall validation: {'PASS' if report.valid else 'FAIL'}")


@dataclass(frozen=True)
class RepairPlan:
    data: bytes
    changes: Tuple[Tuple[int, int, int], ...]
    already_repaired: bool = False
    reasons: Tuple[str, ...] = ()


@dataclass(frozen=True)
class RecoveryScan:
    orphan_candidates: Tuple[Entry, ...]
    length_offset: Optional[int]
    matching_lengths: Tuple[int, ...]


def scan_recovery(data: bytes) -> RecoveryScan:
    """Read-only hypotheses, never proof that residual/deleted data should be live.

    Scan only outside complete entries in the declared directory. At the first
    broken entry (or the terminator), also enumerate checksum-compatible lengths.
    Keep every matching length; trailing zero bytes must not choose one for us.
    """
    report = inspect_bytes(data)
    occupied = bytearray(BANK_SIZE)
    length_offset = report.terminator
    for entry in report.entries:
        if entry.byte_sum is not None:
            occupied[entry.offset:entry.offset + entry.length] = b"\x01" * entry.length
        if not entry.checksum_valid and (
            length_offset is None or entry.offset < length_offset
        ):
            length_offset = entry.offset

    sums = [0]
    used = [0]
    for value, live in zip(data, occupied):
        sums.append(sums[-1] + value)
        used.append(used[-1] + live)

    candidates = []
    for offset in range(HEADER_SIZE, BANK_SIZE - HEADER_SIZE - 1):
        length = u16(data, offset)
        end = offset + length
        if length < HEADER_SIZE or end > BANK_SIZE - 2:
            continue
        if used[end] != used[offset]:
            continue
        byte_sum = sums[end] - sums[offset + 4]
        stored = u16(data, offset + 2)
        if (stored + byte_sum) & 0xFFFF == 0:
            candidates.append(Entry(offset, length, stored, data[offset + 4:offset + 6],
                                    data[offset + 6:offset + 16], byte_sum))

    lengths = []
    if (length_offset is not None and length_offset + HEADER_SIZE <= BANK_SIZE - 2
            and any(data[length_offset + 2:length_offset + HEADER_SIZE])):
        stored = u16(data, length_offset + 2)
        for length in range(HEADER_SIZE, BANK_SIZE - length_offset - 1):
            byte_sum = sums[length_offset + length] - sums[length_offset + 4]
            if (stored + byte_sum) & 0xFFFF == 0:
                lengths.append(length)
    return RecoveryScan(tuple(candidates), length_offset, tuple(lengths))


def length_ranges(lengths: Tuple[int, ...]) -> str:
    """Compact adjacent lengths without hiding that each is a separate hypothesis."""
    ranges = []
    for length in lengths:
        if ranges and length == ranges[-1][1] + 1:
            ranges[-1][1] = length
        else:
            ranges.append([length, length])
    return ", ".join(f"0x{a:04X}" if a == b else f"0x{a:04X}-0x{b:04X}" for a, b in ranges)


def print_recovery_scan(scan: RecoveryScan) -> None:
    print("Recovery scan (hypotheses only; no bytes changed):")
    print(f"  Possible orphaned/deleted entries: {len(scan.orphan_candidates)}")
    for entry in scan.orphan_candidates[:20]:
        print(f"    Offset 0x{entry.offset:04X}, declared length 0x{entry.length:04X}, "
              f"filename={entry.filename!r}, checksum=0x{entry.stored_checksum:04X} matches")
    if len(scan.orphan_candidates) > 20:
        print("    First 20 shown; additional candidates are also unverified.")
    if scan.matching_lengths:
        print(f"  At 0x{scan.length_offset:04X}, {len(scan.matching_lengths)} checksum-compatible "
              f"total lengths (including header): {length_ranges(scan.matching_lengths)}")
    else:
        print("  No alternative length hypotheses found at the first damaged entry/terminator.")
    print("  Checksums cannot prove entry length or whether residual data is live; zero padding can match many lengths.")
    print("  This scan cannot recover missing payload bytes or establish a game's save layout.")


def plan_generic_repair(data: bytes) -> RepairPlan:
    """Repair only bank fields 4..7, assuming intact declared entry lengths.

    Refuse evidence of hidden entries rather than making an empty or shortened
    directory appear successfully restored. No entry, checksum or payload edits.
    """
    report = inspect_bytes(data)
    if report.signature != b"HUBM":
        raise BramError("Generic repair requires the HUBM signature; cannot establish this file's format.")
    if report.terminator is None:
        raise BramError("Directory lengths/bounds are damaged or the terminator is missing; generic repair cannot infer them.")
    if any(not entry.checksum_valid for entry in report.entries):
        raise BramError("Entry checksum failure; cannot distinguish damaged length, checksum, metadata or payload. "
                        "Stored checksums will not be rewritten.")
    if not report.entries and report.residual_nonzero_bytes:
        raise BramError("Directory appears empty but residual data survives; possible lost entry length. "
                        "Refusing to present an empty bank as restored.")
    scan = scan_recovery(data)
    if scan.orphan_candidates or scan.matching_lengths:
        raise BramError("Possible orphaned/deleted entries or a lost length remain; "
                        "generic repair cannot decide which data belongs in the directory.")
    if (report.entries and report.terminator < report.free_offset <= BANK_SIZE - 2
            and u16(data, report.free_offset) == 0):
        raise BramError("Free pointer identifies a later zero-length location than the directory. "
                        "A shortened entry and a bad pointer are both plausible; refusing to shorten the directory.")

    proposed = bytearray(data)
    reasons = []
    if report.memory_end != BASE_ADDRESS + BANK_SIZE:
        struct.pack_into("<H", proposed, 4, BASE_ADDRESS + BANK_SIZE)
        reasons.append("Restore memory boundary to 0x8800: HUBM signature and a raw 2048-byte bank.")
    if report.free_offset != report.terminator:
        struct.pack_into("<H", proposed, 6, BASE_ADDRESS + report.terminator)
        reasons.append(f"Set free pointer to directory terminator at 0x{report.terminator:04X}: "
                       f"{len(report.entries)} complete entries with matching checksums.")
    result = bytes(proposed)
    if not inspect_bytes(result).valid:
        raise BramError("Proposed generic repair failed validation; refusing to write.")
    changes = tuple((i, a, b) for i, (a, b) in enumerate(zip(data, result)) if a != b)
    return RepairPlan(result, changes, reasons=tuple(reasons))


def plan_rondo_repair(data: bytes) -> RepairPlan:
    """Exact known-file patch, never a length guess or a checksum rewrite."""
    require_size(len(data))
    digest = sha256(data)
    if digest == REPAIRED_SHA256:
        if not inspect_bytes(data).valid:
            raise BramError("Already-repaired file unexpectedly failed validation.")
        return RepairPlan(data, (), already_repaired=True)
    if digest != ORIGINAL_SHA256:
        raise BramError(
            f"Profile {PROFILE!r} requires the exact original SHA-256 {ORIGINAL_SHA256}; "
            f"got {digest}. No repair was applied."
        )
    proposed = bytearray(data)
    for offset, before, after in RONDO_PATCH:
        if proposed[offset] != before:
            raise BramError(f"Profile precondition failed at offset 0x{offset:04X}.")
        proposed[offset] = after
    result = bytes(proposed)
    changes = tuple((i, a, b) for i, (a, b) in enumerate(zip(data, result)) if a != b)
    if changes != RONDO_PATCH or sha256(result) != REPAIRED_SHA256:
        raise BramError("Proposed repair does not match the exact expected patch and SHA-256.")
    if not inspect_bytes(result).valid:
        raise BramError("Proposed repair failed structural/checksum validation; refusing to write.")
    return RepairPlan(result, changes)


@dataclass(frozen=True)
class Snapshot:
    data: bytes
    device: int
    inode: int


def read_bank(path: Path) -> Snapshot:
    # O_NONBLOCK prevents a FIFO supplied as an input from hanging the command.
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0))
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode):
            raise BramError(f"Input must be a regular file: {path}")
        require_size(info.st_size)
        data = stream.read(BANK_SIZE + 1)
        require_size(len(data))
    return Snapshot(data, info.st_dev, info.st_ino)


def check_output_path(source: Path, output: Path) -> None:
    if source.resolve(strict=True) == output.resolve(strict=False):
        raise BramError("Input/output aliases are forbidden; choose a separate new output file.")
    # lexists also rejects dangling symlinks; samefile catches hard links/case aliases.
    if os.path.lexists(output):
        if output.exists() and os.path.samefile(source, output):
            raise BramError("Input/output aliases (including hard links) are forbidden.")
        raise BramError(f"Output already exists; refusing to overwrite: {output}")
    if not output.parent.is_dir():
        raise BramError(f"Output parent directory does not exist: {output.parent}")


def verify_original(source: Path, original: Snapshot) -> None:
    if read_bank(source) != original:
        raise BramError("Original changed during the operation; output must not be used.")


def write_verified_copy(source: Path, original: Snapshot, output: Path, proposed: bytes) -> str:
    """Exclusively create a validated copy, then verify file bytes and source identity."""
    if not inspect_bytes(proposed).valid:
        raise BramError("Proposed output failed validation; refusing to write.")
    check_output_path(source, output)
    verify_original(source, original)
    # 'x' uses exclusive creation: a collision after the path check still cannot
    # overwrite a file or follow a symlink at the output name.
    with output.open("xb") as stream:
        created = os.fstat(stream.fileno())
        try:
            if stream.write(proposed) != len(proposed):
                raise BramError("Short write.")
            stream.flush()
            os.fsync(stream.fileno())
        except (OSError, BramError) as exc:
            raise BramError(f"Output write failed; {output} may be incomplete and must not be used: {exc}") from exc
    try:
        written = read_bank(output)
        if (written.device, written.inode) != (created.st_dev, created.st_ino):
            raise BramError("Output file was replaced during verification.")
        if written.data != proposed or not inspect_bytes(written.data).valid:
            raise BramError("Written output does not match the validated proposal.")
        verify_original(source, original)
    except (OSError, BramError) as exc:
        raise BramError(f"Verification failed; output {output} must not be used: {exc}") from exc
    return sha256(written.data)


def print_game_status(data: bytes) -> None:
    if sha256(data) == REPAIRED_SHA256:
        print("Known Rondo repaired save: owner confirmed working in-game.")
    else:
        print("In-game loading of this file is not established by structural/checksum validation.")


def run_inspect(source: Path, recovery_scan: bool = False) -> int:
    original = read_bank(source)
    print(f"Input: {source}\nSize: {len(original.data)} bytes\nSHA-256: {sha256(original.data)}")
    report = inspect_bytes(original.data)
    print_inspection(report)
    digest = sha256(original.data)
    if digest == ORIGINAL_SHA256:
        print(f"Known original recognized: repair profile {PROFILE} is available (use --dry-run first).")
        print("The profile records a surviving 160-byte Rondo entry at 0x0010; the directory currently hides it.")
    elif digest == REPAIRED_SHA256:
        print(f"Known profile {PROFILE}: already repaired.")
    if recovery_scan:
        print_recovery_scan(scan_recovery(original.data))
    print_game_status(original.data)
    return 0 if report.valid else 1


def run_repair(source: Path, output: Path, dry_run: bool, profile: str = "auto") -> int:
    original = read_bank(source)
    digest = sha256(original.data)
    print(f"Input: {source}\nOriginal SHA-256: {digest}")
    check_output_path(source, output)
    if profile == "auto":
        profile = PROFILE if digest in (ORIGINAL_SHA256, REPAIRED_SHA256) else GENERIC_PROFILE
    print(f"Selected profile: {profile}")
    print("Original validation:")
    print_inspection(inspect_bytes(original.data))
    try:
        if profile == PROFILE:
            plan = plan_rondo_repair(original.data)
        elif profile == GENERIC_PROFILE:
            print("Generic repair assumes the declared entry lengths are intact; only bank offsets 0x04-0x07 may change.")
            plan = plan_generic_repair(original.data)
        else:
            raise BramError(f"Unknown repair profile: {profile}")
    except BramError:
        if profile == GENERIC_PROFILE:
            print_recovery_scan(scan_recovery(original.data))
        verify_original(source, original)
        print(f"Original unchanged: PASS (SHA-256 {digest})")
        print("No output created. Include this diagnostic output and the game/device details in a GitHub issue.")
        raise
    if not plan.changes:
        verify_original(source, original)
        if plan.already_repaired:
            print("Already repaired: no byte changes; no output created.")
        else:
            print("No structural repair needed: no byte changes; no output created. This does not prove the save will load.")
        print(f"Original unchanged: PASS (SHA-256 {sha256(original.data)})")
        print("Output SHA-256: none (no output created)")
        print_game_status(plan.data)
        return 0
    for reason in plan.reasons:
        print(f"Reason: {reason}")
    print(f"Byte changes ({len(plan.changes)}):")
    for offset, before, after in plan.changes:
        print(f"  0x{offset:04X}: {before:02X} -> {after:02X}")
    print("Proposed validation:")
    print_inspection(inspect_bytes(plan.data))
    print(f"Proposed output SHA-256: {sha256(plan.data)}")
    if dry_run:
        verify_original(source, original)
        print(f"Dry run: no output created ({output}).")
    else:
        digest = write_verified_copy(source, original, output, plan.data)
        print(f"Written output: {output}\nOutput SHA-256: {digest}")
        print("Written output bytes, structure and checksums: PASS")
    print(f"Original unchanged: PASS (SHA-256 {sha256(original.data)})")
    print_game_status(plan.data)
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    inspect_parser = commands.add_parser("inspect", help="read-only header, directory and checksum validation")
    inspect_parser.add_argument("input", type=Path)
    inspect_parser.add_argument("--scan", action="store_true", help="also report possible orphaned entries and length hypotheses")
    repair_parser = commands.add_parser("repair", help="attempt a cautious repair to a new file")
    repair_parser.add_argument("input", type=Path)
    repair_parser.add_argument("--profile", choices=["auto", PROFILE, GENERIC_PROFILE], default="auto",
                               help="auto (default): exact known Rondo repair if recognized, otherwise generic-structural")
    repair_parser.add_argument("--output", type=Path, required=True)
    repair_parser.add_argument("--dry-run", action="store_true", help="validate and show the proposal without writing")
    args = parser.parse_args(argv)
    try:
        if args.command == "inspect":
            return run_inspect(args.input, args.scan)
        return run_repair(args.input, args.output, args.dry_run, args.profile)
    except (BramError, OSError, RuntimeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
