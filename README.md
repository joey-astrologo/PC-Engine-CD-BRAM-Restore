# PC Engine BRAM Restore

A Python command-line tool for inspecting and cautiously repairing PC Engine /
TurboGrafx-CD backup RAM files, including Turbo EverDrive Pro `.brm` saves.
It checks bank headers, save entries, checksums, and free-space pointers.

Requires **Python 3.8+**, with no external dependencies. Supports raw
**2,048-byte** files only.

## Usage

Inspect a file and scan for possible orphaned entries or damaged entry lengths:

```sh
python3 bram_tool.py inspect path/to/save.brm --scan
```

Preview an attempted repair, then remove `--dry-run` to create the repaired copy:

```sh
python3 bram_tool.py repair path/to/save.brm --output repaired.brm --dry-run
python3 bram_tool.py repair path/to/save.brm --output repaired.brm
python3 bram_tool.py inspect repaired.brm
```

The tool prints its reasoning, byte changes, validation results, and SHA-256
hashes. It never modifies the input or overwrites an existing output. Choose a
new output name if the destination already exists. Dry run creates no file.
Files that need no supported changes also produce no output.

## Repair modes

The default `--profile auto` selects between:

- **`rondo-known-repair`**: reproduces the exact three-byte repair for the supplied
  Rondo of Blood file, requiring its known SHA-256. The owner has **confirmed this
  repaired save works in-game**. This profile is specific to that file, not every
  Rondo save.
- **`generic-structural`**: attempts to restore the memory boundary and free-space
  pointer for other games when the directory is complete and its checksums match.
  It assumes the declared entry lengths are intact and changes only bank-header
  offsets `0x04–0x07`. All entry, payload, checksum, reserved, and residual bytes
  are preserved.

You can select either profile explicitly. For the included Rondo example:

```sh
python3 bram_tool.py repair "corrupt examples/rondo of blood/bram_exp.brm" \
  --profile rondo-known-repair --output rondo_restored.brm --dry-run
```

Generic repair refuses damaged signatures, missing/invalid entry lengths,
checksum failures, and ambiguous directory endings. It also refuses when residual
bytes suggest hidden or deleted entries, including possible false positives.
It never guesses a length or rewrites a checksum to conceal damaged data:
**different lengths can have the same checksum because of trailing zeros**.
The scan provides hypotheses for review, not automatic recovery of those entries.

## If recovery fails

Keep the original and open a GitHub issue with the game, device/emulator, what
happened, the attempted command, and its output. Include an inspection report:

```sh
python3 bram_tool.py inspect path/to/save.brm --scan > bram-report.txt
```

If a proposed repair passes validation but the game still cannot load it, report
that too. Structural/checksum validation alone does not establish in-game success.
Exit codes are `0` for success/no changes, `1` for inspection errors, and `2` for
refused repairs, unsupported files, argument errors, or I/O failures.

Before trying a repaired save, keep a separate original backup. With the console
powered off, rename a copy of the repaired file to the original filename and
replace it in the same SD-card folder.

## Tests

```sh
python3 -m unittest discover -s tests -v
```

The exact Rondo regression tests use the supplied original; they skip if it is
absent rather than fabricate a fixture. Generic cases use synthetic banks.

Format references: [PCE BRAM Manager](https://github.com/Widdiful/PCE_BRAM_Manager)
and its [BRAM format documentation](https://github.com/Widdiful/PCE_BRAM_Manager/wiki/Detailed-contents-of-a-BRAM-file).
# PC-Engine-CD-BRAM-Restore
