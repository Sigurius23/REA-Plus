# Workflow: firmware and embedded software

## Identify the artifact before choosing tools

Record the exact firmware file or partition, SHA-256, device/model/revision as supplied by the user, acquisition method, file size, and any vendor version metadata. Keep raw images immutable and out of the AERE repository. Do not infer a device model solely from a filename.

## Static workflow

1. Inventory the image/container and identify partition or filesystem candidates with a verified format-aware parser.
2. Preserve offsets, partition boundaries, compression/encryption status, endianness, architecture, and parser coverage.
3. If a filesystem parser is used, run it against an immutable/private copy with extraction limits, path normalization, file-count limits, and a record of skipped/corrupt entries.
4. Analyze extracted executables as separate hash-identified artifacts; use an architecture-appropriate native provider and record unsupported code ranges.
5. Distinguish strings/configuration observations from reachable behavior. Treat credentials, keys, and device identifiers as sensitive.
6. If secure boot, encryption, obfuscation, or vendor signing prevents interpretation, record the limitation. Do not infer an absence of features from unreadable regions.

## Explicitly out of scope for AERE v0.2

AERE does not flash firmware, connect to a device, extract archive contents, decrypt protected data, or load code into a process. It has no firmware/filesystem parser or deep disassembler adapter. Those capabilities require separately reviewed, named providers and must report their own exact format, device, version, and coverage limits.
