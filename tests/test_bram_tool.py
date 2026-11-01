"""Synthetic format tests plus regression tests using the supplied, unmodified BRAM."""

import contextlib
import io
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import bram_tool as bram


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = Path(os.environ.get(
    "BRAM_ORIGINAL_FIXTURE", str(ROOT / "corrupt examples/rondo of blood/bram_exp.brm")
))


def entry(payload=b"\x01\x02\x03", identifier=b"\x58\x20", name=b"DRACULA X "):
    """Synthetic entries are for format tests, never a replacement Rondo fixture."""
    body = identifier + name + payload
    return struct.pack("<HH", len(body) + 4, (-sum(body)) & 0xFFFF) + body


def bank(*entries, reserved=b"\0" * 8, residual=b""):
    data = bytearray(2048)
    end = 16 + sum(map(len, entries))
    data[:16] = b"HUBM" + struct.pack("<HH", 0x8800, 0x8000 + end) + reserved
    data[16:end] = b"".join(entries)
    data[end + 2:end + 2 + len(residual)] = residual
    assert len(data) == 2048
    return data


def cli(*args):
    stdout, stderr = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
        status = bram.main([str(arg) for arg in args])
    return status, stdout.getvalue(), stderr.getvalue()


class InspectionTests(unittest.TestCase):
    def test_valid_entry_and_exact_metadata(self):
        report = bram.inspect_bytes(bank(entry()))
        self.assertTrue(report.valid)
        self.assertEqual(report.terminator, 35)
        self.assertEqual(report.free_address, 0x8023)
        saved = report.entries[0]
        self.assertEqual((saved.offset, saved.length), (16, 19))
        self.assertEqual(saved.identifier, b"X ")
        self.assertEqual(saved.filename, b"DRACULA X ")
        self.assertEqual(saved.byte_sum, 786)
        self.assertEqual(saved.stored_checksum, 0xFCEE)

    def test_empty_bank(self):
        report = bram.inspect_bytes(bank())
        self.assertTrue(report.valid)
        self.assertEqual(report.entries, [])
        self.assertEqual(report.terminator, 16)

    def test_reserved_and_residual_bytes_are_legal(self):
        data = bank(entry(), reserved=bytes(range(8)), residual=b"\xFFdeleted\xAA")
        before = bytes(data)
        report = bram.inspect_bytes(data)
        self.assertTrue(report.valid)
        self.assertEqual(report.reserved, bytes(range(8)))
        self.assertEqual(report.residual_nonzero_bytes, 9)
        self.assertEqual(bytes(data), before)

    def test_multiple_entries_including_odd_lengths(self):
        first, second, third = entry(), entry(b"", b"\0\xFF", b"OTHER     "), entry(b"\0\0\xFF\0")
        report = bram.inspect_bytes(bank(first, second, third))
        self.assertTrue(report.valid)
        self.assertEqual([e.offset for e in report.entries], [16, 35, 51])
        self.assertEqual(report.terminator, 71)

    def test_bad_magic_and_boundary(self):
        for offset, value, message in ((0, ord("X"), "signature"), (5, 8, "boundary")):
            with self.subTest(offset=offset):
                data = bank(entry())
                data[offset] = value
                report = bram.inspect_bytes(data)
                self.assertFalse(report.valid)
                self.assertIn(message, " ".join(report.header_errors))
                self.assertEqual(len(report.entries), 1)

    def test_unsupported_sizes_including_truncated_files(self):
        for size in (0, 15, 16, 2047, 2049, 4096):
            with self.subTest(size=size), self.assertRaisesRegex(bram.BramError, "Unsupported size"):
                bram.inspect_bytes(bytes(size))

    def test_short_lengths(self):
        for length in (1, 2, 4, 15):
            with self.subTest(length=length):
                data = bank()
                struct.pack_into("<H", data, 16, length)
                report = bram.inspect_bytes(data)
                self.assertFalse(report.valid)
                self.assertIn("smaller than", " ".join(report.directory_errors))
                self.assertIsNone(report.entries[0].expected_checksum)

    def test_out_of_bounds_entry(self):
        data = bank()
        struct.pack_into("<H", data, 16, 0xFFFF)
        report = bram.inspect_bytes(data)
        self.assertFalse(report.valid)
        self.assertIn("out of bounds", " ".join(report.directory_errors))
        self.assertIsNone(report.entries[0].byte_sum)

    def test_truncated_entry_header_at_end(self):
        data = bank(entry(bytes(2008)))  # First entry ends at 0x7F8.
        struct.pack_into("<H", data, 2040, 16)
        report = bram.inspect_bytes(data)
        self.assertFalse(report.valid)
        self.assertEqual(len(report.entries), 2)
        self.assertIn("Truncated entry header", " ".join(report.directory_errors))

    def test_no_room_for_terminator(self):
        for end in (2047, 2048):
            with self.subTest(end=end):
                data = bank(entry(bytes(end - 32)))
                report = bram.inspect_bytes(data)
                self.assertFalse(report.valid)
                self.assertIn("Missing/truncated directory terminator", " ".join(report.directory_errors))

    def test_terminator_at_last_possible_offset(self):
        report = bram.inspect_bytes(bank(entry(bytes(2014))))
        self.assertTrue(report.valid)
        self.assertEqual(report.terminator, 2046)

    def test_bad_free_pointer_bounds(self):
        for address in (0, 0x7FFF, 0x8000, 0x800F, 0x87FF, 0x8800, 0xFFFF):
            with self.subTest(address=address):
                data = bank(entry())
                struct.pack_into("<H", data, 6, address)
                report = bram.inspect_bytes(data)
                self.assertFalse(report.valid)
                self.assertIn("out of bounds", " ".join(report.header_errors))
                self.assertEqual(len(report.entries), 1)

    def test_free_pointer_mismatch_even_when_it_points_at_zero(self):
        data = bank(entry(bytes(10)))
        for pointer in (0x8020, 0x8040):  # In the payload, or after the real terminator.
            with self.subTest(pointer=pointer):
                struct.pack_into("<H", data, 6, pointer)
                report = bram.inspect_bytes(data)
                self.assertFalse(report.valid)
                self.assertIn("disagrees", " ".join(report.directory_errors))

    def test_free_pointer_to_nonzero_length_does_not_hide_entries(self):
        data = bank(entry(), entry())
        struct.pack_into("<H", data, 6, 0x8010)
        report = bram.inspect_bytes(data)
        self.assertFalse(report.valid)
        self.assertEqual(len(report.entries), 2)
        self.assertIn("does not point to a zero length", " ".join(report.directory_errors))

    def test_checksum_failure_does_not_rewrite_payload_or_checksum(self):
        data = bank(entry(), entry())
        data[32] ^= 1
        before = bytes(data)
        report = bram.inspect_bytes(data)
        self.assertTrue(report.structural_valid)
        self.assertFalse(report.valid)
        self.assertEqual(len(report.checksum_errors), 1)
        self.assertTrue(report.entries[1].checksum_valid)
        self.assertEqual(bytes(data), before)

    def test_checksum_wraps_at_16_bits(self):
        report = bram.inspect_bytes(bank(entry(bytes([255]) * 1000)))
        self.assertTrue(report.valid)
        self.assertGreater(report.entries[0].byte_sum, 65535)
        self.assertEqual((report.entries[0].stored_checksum + report.entries[0].byte_sum) & 0xFFFF, 0)

    def test_zero_padding_cannot_establish_entry_length(self):
        first = bram.inspect_bytes(bank(entry(b"\x01"))).entries[0]
        second = bram.inspect_bytes(bank(entry(b"\x01\0\0\0"))).entries[0]
        self.assertEqual(first.stored_checksum, second.stored_checksum)
        self.assertNotEqual(first.length, second.length)
        hidden = bank(entry())
        hidden[16:18] = b"\0\0"
        struct.pack_into("<H", hidden, 6, 0x8010)
        report = bram.inspect_bytes(hidden)
        self.assertEqual(report.entries, [])  # Never infer a length or resurrect residual bytes.
        self.assertGreater(report.residual_nonzero_bytes, 0)


class FileSafetyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.source = self.directory / "input.brm"
        self.output = self.directory / "output.brm"
        self.source.write_bytes(bank(entry(), residual=b"residual"))
        self.original = bram.read_bank(self.source)

    def test_exclusive_write_and_input_preservation(self):
        digest = bram.write_verified_copy(self.source, self.original, self.output, self.original.data)
        self.assertEqual(self.output.read_bytes(), self.original.data)
        self.assertEqual(bram.read_bank(self.source), self.original)
        self.assertEqual(digest, bram.sha256(self.original.data))

    def test_invalid_proposal_is_not_written(self):
        invalid = bytearray(self.original.data)
        invalid[32] ^= 1
        with self.assertRaisesRegex(bram.BramError, "failed validation"):
            bram.write_verified_copy(self.source, self.original, self.output, invalid)
        self.assertFalse(self.output.exists())

    def test_collision_preserves_both_files(self):
        self.output.write_bytes(b"keep me")
        with self.assertRaisesRegex(bram.BramError, "already exists"):
            bram.write_verified_copy(self.source, self.original, self.output, self.original.data)
        self.assertEqual(self.output.read_bytes(), b"keep me")
        self.assertEqual(self.source.read_bytes(), self.original.data)

    def test_input_output_aliases(self):
        for output in (self.source, self.directory / "." / "input.brm"):
            with self.subTest(output=output), self.assertRaisesRegex(bram.BramError, "aliases"):
                bram.check_output_path(self.source, output)

    def test_symlink_and_hardlink_aliases(self):
        for link_type in ("symlink", "hardlink"):
            with self.subTest(link_type=link_type):
                alias = self.directory / link_type
                if link_type == "symlink":
                    alias.symlink_to(self.source)
                else:
                    os.link(self.source, alias)
                with self.assertRaisesRegex(bram.BramError, "aliases"):
                    bram.write_verified_copy(self.source, self.original, alias, self.original.data)
        self.assertEqual(self.source.read_bytes(), self.original.data)

    def test_output_dangling_symlink_or_directory_is_rejected(self):
        self.output.symlink_to(self.directory / "missing.brm")
        with self.assertRaisesRegex(bram.BramError, "already exists"):
            bram.check_output_path(self.source, self.output)
        self.assertFalse((self.directory / "missing.brm").exists())
        with self.assertRaisesRegex(bram.BramError, "already exists"):
            bram.check_output_path(self.source, self.directory)

    def test_missing_output_parent(self):
        with self.assertRaisesRegex(bram.BramError, "parent directory"):
            bram.check_output_path(self.source, self.directory / "missing" / "out.brm")

    def test_collision_between_precheck_and_open(self):
        def race(source, output):
            output.write_bytes(b"created concurrently")

        with mock.patch.object(bram, "check_output_path", side_effect=race):
            with self.assertRaises(FileExistsError):
                bram.write_verified_copy(self.source, self.original, self.output, self.original.data)
        self.assertEqual(self.output.read_bytes(), b"created concurrently")
        self.assertEqual(self.source.read_bytes(), self.original.data)

    def test_input_change_before_write_is_detected(self):
        changed = bytearray(self.original.data)
        changed[-1] ^= 1
        self.source.write_bytes(changed)
        with self.assertRaisesRegex(bram.BramError, "Original changed"):
            bram.write_verified_copy(self.source, self.original, self.output, self.original.data)
        self.assertFalse(self.output.exists())

    def test_output_corruption_during_readback_is_detected(self):
        real_read = bram.read_bank

        def corrupt_output(path):
            if path == self.output:
                data = bytearray(path.read_bytes())
                data[-1] ^= 1  # Still structurally valid, but differs from the proposal.
                path.write_bytes(data)
            return real_read(path)

        with mock.patch.object(bram, "read_bank", side_effect=corrupt_output):
            with self.assertRaisesRegex(bram.BramError, "must not be used"):
                bram.write_verified_copy(self.source, self.original, self.output, self.original.data)
        self.assertEqual(self.source.read_bytes(), self.original.data)

    def test_input_change_during_write_is_detected(self):
        real_read = bram.read_bank

        def change_original(path):
            if path == self.output:
                changed = bytearray(self.original.data)
                changed[-1] ^= 1
                self.source.write_bytes(changed)
            return real_read(path)

        with mock.patch.object(bram, "read_bank", side_effect=change_original):
            with self.assertRaisesRegex(bram.BramError, "Original changed"):
                bram.write_verified_copy(self.source, self.original, self.output, self.original.data)

    def test_write_failure_is_reported_and_original_preserved(self):
        with mock.patch.object(bram.os, "fsync", side_effect=OSError("simulated disk failure")):
            with self.assertRaisesRegex(bram.BramError, "must not be used"):
                bram.write_verified_copy(self.source, self.original, self.output, self.original.data)
        self.assertEqual(self.source.read_bytes(), self.original.data)

    def test_profile_rejects_unknown_file(self):
        status, stdout, stderr = cli("repair", self.source, "--profile", bram.PROFILE, "--output", self.output)
        self.assertEqual(status, 2)
        self.assertIn("requires the exact original SHA-256", stderr)
        self.assertIn(bram.sha256(self.original.data), stdout)
        self.assertFalse(self.output.exists())
        self.assertEqual(self.source.read_bytes(), self.original.data)

    def test_inspect_cli_status_and_metadata(self):
        status, stdout, stderr = cli("inspect", self.source)
        self.assertEqual((status, stderr), (0, ""))
        for text in ("Bank header: PASS", "DRACULA X ", "Checksum: PASS", "Structural validation: PASS"):
            self.assertIn(text, stdout)
        invalid = bytearray(self.original.data)
        invalid[32] ^= 1
        self.source.write_bytes(invalid)
        status, stdout, stderr = cli("inspect", self.source)
        self.assertEqual((status, stderr), (1, ""))
        self.assertIn("Checksum: FAIL", stdout)

    def test_cli_file_errors_have_no_traceback(self):
        self.output.write_bytes(b"short")
        for path in (self.output, self.directory / "missing", self.directory):
            with self.subTest(path=path):
                status, stdout, stderr = cli("inspect", path)
                self.assertEqual(status, 2)
                self.assertIn("ERROR:", stderr)
                self.assertNotIn("Traceback", stderr)

    def test_script_entry_point(self):
        result = subprocess.run([sys.executable, str(ROOT / "bram_tool.py"), "inspect", str(self.source)],
                                capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Overall validation: PASS", result.stdout)


class GenericRepairTests(unittest.TestCase):
    def test_repairs_boundary_preserving_all_other_bytes(self):
        expected = bank(entry(name=b"OTHER GAME"), entry(b"\x80\0\xFF"),
                        reserved=bytes(range(8)))
        expected[-4:] = b"tail"  # Residual bytes that do not resemble another entry.
        damaged = bytearray(expected)
        damaged[4:6] = b"\xFF\xFF"
        plan = bram.plan_generic_repair(damaged)
        self.assertEqual(plan.data, expected)
        self.assertEqual([i for i, a, b in plan.changes], [4, 5])
        self.assertIn("memory boundary", plan.reasons[0])

    def test_repairs_invalid_or_early_free_pointers(self):
        expected = bytes(bank(entry(), entry(b"\xFF\x00")))
        for pointer in (0, 0x8000, 0x8010, 0x8020, 0x8800, 0xFFFF):
            with self.subTest(pointer=pointer):
                damaged = bytearray(expected)
                struct.pack_into("<H", damaged, 6, pointer)
                plan = bram.plan_generic_repair(damaged)
                self.assertEqual(plan.data, expected)
                self.assertTrue(all(offset in (6, 7) for offset, _, _ in plan.changes))

    def test_repairs_pointer_to_nonzero_residual_bytes(self):
        expected = bank(entry())
        expected[2046] = 1
        damaged = bytearray(expected)
        struct.pack_into("<H", damaged, 6, 0x87FE)
        self.assertEqual(bram.plan_generic_repair(damaged).data, expected)

    def test_repairs_both_fields_of_pristine_empty_bank(self):
        expected = bank(reserved=b"reserved")
        damaged = bytearray(expected)
        damaged[4:8] = b"\x00\x08\x00\x00"
        plan = bram.plan_generic_repair(damaged)
        self.assertEqual(plan.data, expected)
        self.assertEqual(len(plan.reasons), 2)

    def test_already_valid_is_no_op(self):
        with_residual = bank(entry())
        with_residual[-4:] = b"tail"
        for data in (bank(), bank(entry()), with_residual):
            with self.subTest(data=data[:36]):
                plan = bram.plan_generic_repair(data)
                self.assertEqual(plan.data, data)
                self.assertEqual(plan.changes, ())
                self.assertFalse(plan.already_repaired)  # No claim of a verified prior repair.

    def test_refuses_invalid_signature(self):
        data = bank(entry())
        data[0] = 0
        with self.assertRaisesRegex(bram.BramError, "requires the HUBM signature"):
            bram.plan_generic_repair(data)

    def test_refuses_checksum_failure_even_with_fixable_header(self):
        for offset in (18, 20, 22, 32):  # Checksum, ID, filename and payload.
            with self.subTest(offset=offset):
                data = bank(entry())
                data[5] = 8
                data[offset] ^= 1
                before = bytes(data)
                with self.assertRaisesRegex(bram.BramError, "checksum failure"):
                    bram.plan_generic_repair(data)
                self.assertEqual(data, before)

    def test_refuses_bad_lengths_or_missing_terminator(self):
        for length in (1, 15, 2031, 2032, 0xFFFF):
            with self.subTest(length=length):
                data = bank(entry())
                struct.pack_into("<H", data, 16, length)
                with self.assertRaisesRegex(bram.BramError, "lengths/bounds"):
                    bram.plan_generic_repair(data)

    def test_refuses_lost_first_entry_length(self):
        data = bank(entry())
        data[5] = 8
        data[16:18] = b"\0\0"
        with self.assertRaisesRegex(bram.BramError, "appears empty but residual data"):
            bram.plan_generic_repair(data)

    def test_refuses_lost_middle_entry_length(self):
        data = bank(entry(), entry(), entry())
        data[35:37] = b"\0\0"
        with self.assertRaisesRegex(bram.BramError, "orphaned/deleted"):
            bram.plan_generic_repair(data)

    def test_refuses_orphaned_entry_beyond_terminator(self):
        data = bank(entry(), residual=bytes(entry(b"second", name=b"ORPHAN    ")))
        data[5] = 8
        scan = bram.scan_recovery(data)
        self.assertTrue(any(e.offset == 37 and e.filename == b"ORPHAN    " for e in scan.orphan_candidates))
        with self.assertRaisesRegex(bram.BramError, "orphaned/deleted"):
            bram.plan_generic_repair(data)

    def test_refuses_residual_bytes_that_coincidentally_resemble_an_entry(self):
        data = bank(entry(), residual=b"old data")
        # The final ASCII byte followed by zeros can itself look like a length
        # with an all-zero body/checksum. Do not treat this weak evidence as a save.
        self.assertTrue(bram.scan_recovery(data).orphan_candidates)
        with self.assertRaisesRegex(bram.BramError, "orphaned/deleted"):
            bram.plan_generic_repair(data)

    def test_refuses_later_zero_pointer_without_guessing_which_end_is_correct(self):
        data = bank(entry())
        struct.pack_into("<H", data, 6, 0x8080)
        with self.assertRaisesRegex(bram.BramError, "shortened entry and a bad pointer"):
            bram.plan_generic_repair(data)

    def test_does_not_accept_accidentally_shortened_zero_padded_entry(self):
        data = bank(entry(b"\x01" + bytes(20)))
        struct.pack_into("<H", data, 16, 17)  # The checksum still agrees.
        self.assertTrue(bram.inspect_bytes(data).entries[0].checksum_valid)
        with self.assertRaisesRegex(bram.BramError, "shortened entry"):
            bram.plan_generic_repair(data)

    def test_scan_retains_multiple_lengths_and_changes_nothing(self):
        data = bank(entry(b"\x01\0\0\0"))
        data[16:18] = b"\0\0"
        before = bytes(data)
        scan = bram.scan_recovery(data)
        self.assertEqual(scan.length_offset, 16)
        self.assertIn(17, scan.matching_lengths)
        self.assertIn(20, scan.matching_lengths)
        self.assertGreater(len(scan.matching_lengths), 2)
        self.assertEqual(bytes(data), before)

    def test_even_unique_checksum_length_is_not_automatic_recovery(self):
        data = bank(entry(bytes([1]) * 2014))
        data[16:18] = b"\0\0"
        self.assertEqual(bram.scan_recovery(data).matching_lengths, (2030,))
        with self.assertRaises(bram.BramError):
            bram.plan_generic_repair(data)

    def test_scan_does_not_identify_live_payload_as_orphan(self):
        data = bank(entry(bytes(entry(b"nested"))))
        scan = bram.scan_recovery(data)
        self.assertEqual(scan.orphan_candidates, ())
        self.assertEqual(scan.matching_lengths, ())

    def test_scan_can_find_candidate_at_last_possible_header(self):
        data = bank()
        data[2030:2046] = entry(b"")
        scan = bram.scan_recovery(data)
        self.assertTrue(any(e.offset == 2030 and e.length == 16 for e in scan.orphan_candidates))

    def test_generic_and_scan_reject_unsupported_sizes(self):
        for function in (bram.plan_generic_repair, bram.scan_recovery):
            with self.subTest(function=function.__name__), self.assertRaisesRegex(bram.BramError, "Unsupported size"):
                function(bytes(2047))


class GenericCliTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.source = Path(self.temp.name) / "other-game.brm"
        self.output = Path(self.temp.name) / "restored.brm"
        self.expected = bytes(bank(entry(name=b"OTHER GAME")))
        self.damaged = bytearray(self.expected)
        self.damaged[5] = 8
        self.source.write_bytes(self.damaged)

    def test_default_auto_selects_generic_and_writes_verified_copy(self):
        status, stdout, stderr = cli("repair", self.source, "--output", self.output)
        self.assertEqual((status, stderr), (0, ""))
        self.assertIn("Selected profile: generic-structural", stdout)
        self.assertIn("Reason: Restore memory boundary", stdout)
        self.assertIn("Written output bytes, structure and checksums: PASS", stdout)
        self.assertIn("Original unchanged: PASS", stdout)
        self.assertIn(bram.sha256(self.expected), stdout)
        self.assertNotIn("confirmed working in-game", stdout)
        self.assertEqual(self.output.read_bytes(), self.expected)
        self.assertEqual(self.source.read_bytes(), self.damaged)

    def test_explicit_generic_dry_run(self):
        status, stdout, stderr = cli("repair", self.source, "--profile", bram.GENERIC_PROFILE,
                                     "--output", self.output, "--dry-run")
        self.assertEqual((status, stderr), (0, ""))
        self.assertIn("Byte changes (1)", stdout)
        self.assertIn("Proposed output SHA-256:", stdout)
        self.assertFalse(self.output.exists())
        self.assertEqual(self.source.read_bytes(), self.damaged)

    def test_refusal_includes_diagnostics_and_never_writes(self):
        self.damaged[16:18] = b"\0\0"
        self.source.write_bytes(self.damaged)
        for dry in ([], ["--dry-run"]):
            with self.subTest(dry=dry):
                status, stdout, stderr = cli("repair", self.source, "--output", self.output, *dry)
                self.assertEqual(status, 2)
                self.assertIn("appears empty", stderr)
                self.assertIn("Recovery scan", stdout)
                self.assertIn("GitHub issue", stdout)
                self.assertIn(bram.sha256(self.damaged), stdout)
                self.assertFalse(self.output.exists())
                self.assertEqual(self.source.read_bytes(), self.damaged)

    def test_inspect_scan_is_read_only(self):
        status, stdout, stderr = cli("inspect", self.source, "--scan")
        self.assertEqual((status, stderr), (1, ""))
        self.assertIn("Recovery scan (hypotheses only", stdout)
        self.assertEqual(self.source.read_bytes(), self.damaged)

    def test_valid_input_no_op_does_not_claim_game_success(self):
        self.source.write_bytes(self.expected)
        status, stdout, stderr = cli("repair", self.source, "--output", self.output)
        self.assertEqual((status, stderr), (0, ""))
        self.assertIn("No structural repair needed", stdout)
        self.assertIn("does not prove the save will load", stdout)
        self.assertFalse(self.output.exists())

    def test_generic_cli_rejects_collisions_and_aliases(self):
        self.output.write_bytes(b"keep me")
        for output in (self.output, self.source):
            with self.subTest(output=output):
                status, stdout, stderr = cli("repair", self.source, "--output", output)
                self.assertEqual(status, 2)
        self.assertEqual(self.output.read_bytes(), b"keep me")
        self.assertEqual(self.source.read_bytes(), self.damaged)


class SuppliedRondoTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not FIXTURE.is_file():
            raise unittest.SkipTest(f"Actual original fixture unavailable: {FIXTURE}; not fabricated")
        cls.original = FIXTURE.read_bytes()
        if bram.sha256(cls.original) != bram.ORIGINAL_SHA256:
            raise AssertionError(f"Supplied original fixture has unexpected SHA-256: {FIXTURE}")

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.source = Path(self.temp.name) / "bram_exp.brm"
        self.output = Path(self.temp.name) / "bram_repaired.brm"
        self.source.write_bytes(self.original)

    def test_exact_three_byte_repair_and_known_hash(self):
        self.assertEqual(len(self.original), 2048)
        self.assertEqual(self.original[:32].hex(), "4855424d00081080000000000000000000007ef7582044524143554c41205820")
        self.assertFalse(bram.inspect_bytes(self.original).valid)
        plan = bram.plan_rondo_repair(self.original)
        self.assertEqual(plan.changes, ((5, 8, 0x88), (6, 0x10, 0xB0), (16, 0, 0xA0)))
        changed = [i for i in range(2048) if self.original[i] != plan.data[i]]
        self.assertEqual(changed, [5, 6, 16])
        self.assertEqual(bram.sha256(plan.data), bram.REPAIRED_SHA256)
        self.assertEqual(plan.data[0x12:], self.original[0x12:])
        report = bram.inspect_bytes(plan.data)
        self.assertTrue(report.valid)
        self.assertEqual(report.terminator, 0xB0)
        saved = report.entries[0]
        self.assertEqual((saved.length, saved.byte_sum, saved.stored_checksum), (160, 2178, 0xF77E))
        self.assertEqual(saved.identifier, b"X ")
        self.assertEqual(saved.filename, b"DRACULA X ")
        self.assertEqual(FIXTURE.read_bytes(), self.original)

    def test_dry_run_creates_nothing(self):
        status, stdout, stderr = cli("repair", self.source, "--profile", bram.PROFILE,
                                     "--output", self.output, "--dry-run")
        self.assertEqual((status, stderr), (0, ""))
        self.assertIn("Byte changes (3)", stdout)
        self.assertIn(bram.REPAIRED_SHA256, stdout)
        self.assertIn("Dry run: no output created", stdout)
        self.assertFalse(self.output.exists())
        self.assertEqual(self.source.read_bytes(), self.original)

    def test_cli_repair_readback_and_original_preservation(self):
        status, stdout, stderr = cli("repair", self.source, "--profile", bram.PROFILE, "--output", self.output)
        self.assertEqual((status, stderr), (0, ""))
        self.assertIn("Written output bytes, structure and checksums: PASS", stdout)
        self.assertIn("Original unchanged: PASS", stdout)
        self.assertEqual(bram.sha256(self.output.read_bytes()), bram.REPAIRED_SHA256)
        self.assertEqual(self.source.read_bytes(), self.original)
        self.assertEqual(FIXTURE.read_bytes(), self.original)

    def test_cli_recognizes_already_repaired_without_creating_output(self):
        self.source.write_bytes(bram.plan_rondo_repair(self.original).data)
        status, stdout, stderr = cli("repair", self.source, "--profile", bram.PROFILE, "--output", self.output)
        self.assertEqual((status, stderr), (0, ""))
        self.assertIn("Already repaired", stdout)
        self.assertFalse(self.output.exists())

    def test_near_match_is_rejected(self):
        for offset in (0x20, 0xB2, 0x7FF):
            with self.subTest(offset=offset):
                changed = bytearray(self.original)
                changed[offset] ^= 1
                with self.assertRaisesRegex(bram.BramError, "exact original SHA-256"):
                    bram.plan_rondo_repair(bytes(changed))

    def test_default_auto_still_makes_exact_rondo_repair(self):
        status, stdout, stderr = cli("repair", self.source, "--output", self.output)
        self.assertEqual((status, stderr), (0, ""))
        self.assertIn("Selected profile: rondo-known-repair", stdout)
        self.assertIn("owner confirmed working in-game", stdout)
        self.assertEqual(bram.sha256(self.output.read_bytes()), bram.REPAIRED_SHA256)
        self.assertEqual(FIXTURE.read_bytes(), self.original)

    def test_generic_refuses_to_hide_rondo_or_guess_length(self):
        status, stdout, stderr = cli("repair", self.source, "--profile", bram.GENERIC_PROFILE,
                                     "--output", self.output)
        self.assertEqual(status, 2)
        self.assertIn("possible lost entry length", stderr)
        self.assertIn("checksum-compatible total lengths", stdout)
        self.assertFalse(self.output.exists())

    def test_auto_never_treats_near_match_as_known_rondo(self):
        changed = bytearray(self.original)
        changed[-1] ^= 1
        self.source.write_bytes(changed)
        status, stdout, stderr = cli("repair", self.source, "--output", self.output)
        self.assertEqual(status, 2)
        self.assertIn("Selected profile: generic-structural", stdout)
        self.assertNotIn("owner confirmed working in-game", stdout)
        self.assertFalse(self.output.exists())

    def test_auto_recognizes_repaired_hash_as_confirmed_no_op(self):
        self.source.write_bytes(bram.plan_rondo_repair(self.original).data)
        status, stdout, stderr = cli("repair", self.source, "--output", self.output)
        self.assertEqual((status, stderr), (0, ""))
        self.assertIn("Already repaired", stdout)
        self.assertIn("owner confirmed working in-game", stdout)
        self.assertFalse(self.output.exists())

    def test_cli_rejects_collision_even_in_dry_run(self):
        self.output.write_bytes(b"existing output")
        for dry in ([], ["--dry-run"]):
            with self.subTest(dry=dry):
                status, stdout, stderr = cli("repair", self.source, "--profile", bram.PROFILE,
                                             "--output", self.output, *dry)
                self.assertEqual(status, 2)
                self.assertIn("already exists", stderr)
                self.assertEqual(self.output.read_bytes(), b"existing output")
                self.assertEqual(self.source.read_bytes(), self.original)


if __name__ == "__main__":
    unittest.main()
