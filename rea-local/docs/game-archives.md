# Game engine archives

`inspect_game_archive` / `inspect-game-archive` lists the archives five game
engines ship their content in, and previews single entries:

| Format         | Files                                                                   | Engines                                    |
| -------------- | ----------------------------------------------------------------------- | ------------------------------------------ |
| Godot pack     | `.pck` (formats 1-3), or a pack embedded in an exported game executable | Godot 3.x and 4.x                          |
| Ren'Py archive | `.rpa` (RPA-2.0, 3.0, 3.2, 4.0)                                         | Ren'Py visual novels                       |
| Valve VPK      | `pak01_dir.vpk` and single-file `.vpk` (versions 1 and 2)               | Source and Source 2 games and their mods   |
| Doom WAD       | IWAD and PWAD                                                           | Doom-engine games, source ports and mods   |
| Unreal pak     | `.pak` (versions 1-11)                                                  | Unreal Engine 4 and 5 games and their mods |

REA+ reads the archive's own index natively. Nothing is extracted, mounted or
executed, and no tool configuration is needed.

```sh
rea inspect-game-archive ~/Games/MyGame/MyGame.pck --extension gd --json
rea inspect-game-archive ~/Games/MyGame/MyGame.x86_64 --entry project.godot --json
rea inspect-game-archive ~/Games/vn/game/archive.rpa --entry script.rpy --json
rea inspect-game-archive ~/Games/doom/freedoom2.wad --query MAP01/ --json
rea inspect-game-archive ~/Games/ue/Game/Content/Paks/pakchunk0-Windows.pak --extension ini --json
```

```json
{
  "name": "inspect_game_archive",
  "arguments": {
    "path": "/games/vn/game/scripts.rpa",
    "extension": "rpyc"
  }
}
```

## What the result contains

- `archive`: path, SHA-256, size, format and version, the Godot engine version
  that wrote a pack, where an embedded pack starts (`embedded_at`), flags such
  as `directory_encrypted`, `xor_obfuscated_index` or `multi_chunk`, entry
  count and bytes, entries and bytes per extension, and format notes (for
  example the number of WAD maps, or the sibling VPK chunks the data lives
  in).
- `page` and `entries`: one page of entries matching `query` (a
  case-insensitive path substring) and `extension`. Each entry has its path,
  size, offset in the selected file, the sibling archive holding its data
  (`stored_in`, VPK chunks such as `pak01_003.vpk`), bytes stored inside the
  index itself (`inline_bytes`: Ren'Py prefixes, VPK preload data), the bytes
  it occupies in the archive (`stored_size`), its pak `compression` method,
  `encrypted` and `removed` flags, and its WAD `group`. Stored checksums
  (Godot MD5, VPK CRC32, pak SHA-1) are recomputed: `verified` is true or false when
  the entry's bytes are in the selected file, and null otherwise.
- `entry` (with `entry`): the selected entry's SHA-256 and up to
  `preview_bytes` (default 4096, at most 64 KiB) as UTF-8 text, or as hex
  when the entry has a NUL in its first 8 KiB or does not decode. Encrypted
  entries, Godot removals and data in sibling VPK chunks are reported as
  unavailable with the reason.

### Per-format notes

- **Godot**: paths are listed without `res://`. Packs appended to an exported
  executable are found through Godot's `[size][GDPC]` trailer. Godot 4.4+
  patch packs can mark paths as removed. Encrypted files are flagged; an
  encrypted directory is detected and its entry count reported, but nothing
  is decrypted.
- **Ren'Py**: offsets and lengths are un-XORed with the header key. An entry's
  bytes are its index prefix followed by its data, as Ren'Py's own loader
  reads them. The index is a Python pickle; REA+ decodes only dicts, lists,
  tuples, strings, bytes and integers, plus Python's two spellings of
  `bytes`, and refuses any other global or opcode without running it.
- **VPK**: a `_dir.vpk` usually keeps file data in sibling chunks. REA+ lists
  them by name but reads only the selected file, so those entries have no
  preview or checksum check. Preload bytes and data stored in the directory
  file itself are read.
- **WAD**: lumps after a map marker are listed as `MAP01/THINGS` (UDMF maps
  run from `TEXTMAP` to `ENDMAP`). Lumps between `S_START`/`S_END`,
  `F_START`/`F_END`, `P_START`/`P_END` and similar markers are listed as
  `sprites/…`, `flats/…` and `patches/…`. Repeated names get `#2`, `#3`
  suffixes so every lump can be previewed.
- **Unreal pak**: the footer is located for every version from 1 to 11 (8A
  and 8B included); the mount point and the footer's compression method
  names are reported in notes. Pak 10+ indexes are read through the full
  directory index and its bit-packed entries, including entries kept out of
  the encoded blob. Zlib, Gzip and Zstd blocks are decompressed for previews
  and checksums; Oodle and other methods are listed but not decoded. Each
  entry's SHA-1 is checked against the stored bytes (as Unreal's packer
  writes it) or the uncompressed bytes (as some modding tools write it).
  Deleted records of patch paks are reported as removed. Encrypted indexes
  and entries are flagged and not decrypted; no AES key is accepted.

## Boundaries

- Other engines' archives (Unreal IoStore `.utoc`/`.ucas`, RPG Maker, GameMaker `data.win`,
  Bethesda BSA/BA2) are refused. Unity bundles have their own tool,
  [`inspect_unity_assets`](./unity-assets.md).
- Godot pack format 4 (sparse bundles and delta patches, in development after
  Godot 4.5) and Godot packs located only through an executable's `pck`
  section, without the trailer, are not read.
- Ren'Py RPA-1.0 (index in a separate `.rpi` file) and obfuscated variants
  such as ZiX are refused.
- Archives up to 2 GiB are read into memory, and checksum checks stop after
  256 MiB of entries per page.

## Verification

`tests/boundary/providers/gamearchives/gameArchive.test.ts` builds every
format in source: Godot packs of formats 1, 2 and 3 with removals, encrypted
files, an encrypted directory and an embedded pack; Ren'Py RPA-3.0 with
prefixes and RPA-2.0; VPK 1 and 2 with preload data and sibling chunks; a
PWAD with binary and UDMF maps, sprites with sub-markers and a duplicate
lump; and Unreal paks of versions 3, 5, 6, 8B and 11 with multi-block zlib
entries, absolute and relative block offsets, a deleted record, an Oodle
entry, UTF-16 names, an unencoded pak 11 entry and an encrypted index. The
real tools read those fixtures to the same contents: Godot 3.6 and
4.5.1 (`load_resource_pack`), Ren'Py's loader code, the `vpk` Python package
(CRCs included), omgifol (which does not recognise UDMF maps) and repak
0.2.2 (which reads every pak fixture except the unencoded pak 11 entry, a
case it does not implement). `src/gamearchives/SafePickle.test.ts` decodes
pickles written by Python 3.13 at protocols 2 and 5, and refuses
`os.system` payloads at protocols 2 and 4.

Two real-data lanes:

- `REA_VERIFY_GODOT_BIN`: an official Godot 4.x binary. The test packs files
  with the engine's `PCKPacker`, loads the pack back into the engine, and
  compares every path, size and MD5 with REA+. It passed with Godot 4.3
  (format 2), 4.4.1 (format 2) and 4.5.1 (format 3).
- `REA_VERIFY_REPAK_BIN`: trumank's repak 0.2.2, the pak tool Unreal modders
  use. The test packs files as pak V1, V3, V5, V7, V8A, V8B, V9, V10 and V11,
  and as V11 with Zlib, Gzip and Zstd. It then compares every path and
  content hash with `repak hash-list` and checks that every SHA-1 verifies.
  During development all 18 versions and codec combinations repak writes
  matched.
- `REA_VERIFY_FREEDOOM_DIR`: the Freedoom 0.13.0 release. REA+ matched
  omgifol 0.5.1 on all 3,163 and 3,610 lumps (names, offsets and sizes), 36
  and 32 maps, the sprite, flat and patch namespaces, and lump hashes.

During development, packs written by Godot 3.6, 4.3, 4.4.1 and 4.5.1, Ren'Py
archives written with Ren'Py's own archiver class, and a VPK written by the
`vpk` package were also compared. Godot's MD5s, Ren'Py's loader hashes and
the VPK CRCs agreed. unrpa 2.3.0 disagreed on entries with index prefixes:
it counts the prefix inside the stored length, and Ren'Py's loader does not.
REA+ follows Ren'Py.
