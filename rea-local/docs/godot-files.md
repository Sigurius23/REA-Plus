# Godot files

`inspect_godot_file` / `inspect-godot-file` decodes the binary files Godot
3 and 4 games ship. Nothing is loaded or run, and no Godot installation is
needed. It reads:

- binary resources and scenes: `.res`, `.scn`, and the binary forms that
  exports turn `.tres` and `.tscn` into. Plain and RSCC-compressed files
  are both read.
- compiled GDScript: `.gdc` from Godot 3.0–3.6 and from Godot 4.3 and
  later, and Godot 3's encrypted `.gde` when you supply the key.
- saves and settings:
  - values written with `store_var` or `var_to_bytes`;
  - files written with `open_compressed` (GCPF);
  - files written with `open_encrypted` / `open_encrypted_with_pass` (GDEC),
    with the key or password;
  - `project.binary`.

You can point it at a loose file, or at a `.pck` or a game executable with
an embedded pack plus an `entry`. Exports rename files: `player.gd` becomes
`player.gdc`, and `level.tscn` becomes `.godot/exported/…/level.scn`. So
an entry named by its original path follows the `.remap` file the export
left behind. `inspect_game_archive` lists a pack's entries.

```sh
rea inspect-godot-file ~/Games/MyGame/MyGame.pck --entry res://scripts/player.gd --json
rea inspect-godot-file MyGame.pck --entry res://scenes/level_1.tscn --json
rea inspect-godot-file MyGame.pck --entry res://scenes/level_1.tscn --view connections --json
rea inspect-godot-file MyGame.pck --entry res://scenes/level_1.tscn --view properties --node Player --json
rea inspect-godot-file MyGame.pck --entry project.binary --query input/ --json
MYGAME_PASS='the password' rea inspect-godot-file ~/.local/share/godot/app_userdata/MyGame/save.dat --password_env MYGAME_PASS --json
```

```json
{
  "name": "inspect_godot_file",
  "arguments": {
    "path": "/games/MyGame/MyGame.pck",
    "entry": "res://scripts/player.gd",
    "view": "source"
  }
}
```

## What the result contains

- `file`: path, SHA-256 and size. `entry`: the pack entry that was read, the
  path it was remapped from, and the pack's engine version.
- `layers`: GDEC decryption and GCPF decompression that were removed.
- `kind`: `resource`, `scene`, `script` or `variant`. Each kind has its own
  header:
  - `resource`: engine version, format, type, UID, script class, flags and
    counts. Compressed resources list their compression among the flags.
  - `script`: tokenizer version, the engines that write it, and counts.
  - `variant`: the encoding (`store_var`, `var_to_bytes` or
    `project_settings`) and the engine whose type numbers it uses.
- `summary`, `page` and one view, filtered by `resource`, `node` and
  `query`:
  - `resources`: external resources by path and UID, then the internal
    ones by the id `SubResource()` uses. `main` is the file's own.
  - `properties`: every stored property, in Godot's text notation:
    `Vector2(1, 2)`, `ExtResource("res://icon.png")`,
    `SubResource("Gradient_x1")`, `PackedInt32Array(…)`. Each row has its
    owner: a resource id, or a scene node.
  - `nodes` (scenes): the tree, by path. Each node has its parent, type,
    the scene it instances, groups and property count. `node` limits the
    view to a subtree.
  - `connections` (scenes): signal, source, target, method, flags, binds
    and unbinds.
  - `source` (scripts): GDScript rebuilt on its original line numbers.
  - `tokens` (scripts): the token stream with types and lines.
  - `values` (saves): every value by path (`$[0].player.inventory[2]`),
    with its type and text. Objects saved with `full_objects` list their
    properties.

### Reading compiled GDScript

A `.gdc` file holds the tokenizer's output, not bytecode: identifiers,
constants, the line of every token and, in Godot 4, the column where each
logical line starts. So `source` puts every token back on its own line, with
indentation from the token stream (one tab per level).

Comments, blank lines and the original spacing are not stored. Spacing is
regenerated. Godot 4 stores `-1` as a single literal, and Godot 3 stores `&&`
as `and`.

## Boundaries

- Text resources (`.tres`, `.tscn`) and plain `.gd` scripts are already
  readable text and are not parsed.
- Godot 2 resources and bytecode are not read. Tokenizer versions after 101
  are refused until their tables are added.
- Godot 3.1 and 3.2–3.6 both write bytecode 13, but 3.2 inserted built-in
  functions into the middle of the table. Names follow 3.2–3.6, so a 3.1
  script can show wrong built-in names.
- Encrypted files need the game's key, which REA+ does not recover:
  - `key_env` names an environment variable holding the 64-hex-digit
    AES-256 key;
  - `password_env` names one holding an `open_encrypted_with_pass`
    password.

  The key is never an input or part of the evidence. Pack entries and
  directories encrypted with the script key are not decrypted.

- `store_var` data does not say which engine wrote it, and Godot 3 and 4
  number types differently. `engine: "auto"` keeps the reading that uses
  every byte, and `also_reads_as` reports when both engines' readings fit.
- Values are cut at 4000 characters, and containers at 1000 in the
  `values` view.
- Files over 2 GiB are refused.

## Verification

`tests/boundary/providers/godot/godotFile.test.ts` builds every format byte
by byte from Godot's sources: Godot 3 and 4 resources, a scene, compiled
scripts of both families, saves, `project.binary`, GCPF and GDEC. Then it
checks:

- every value type;
- scene trees, instanced scenes, groups and connections;
- rebuilt source;
- `.remap` lookups in packs and in an executable with an embedded pack;
- refusals of views, nodes, resources, entries and keys that do not fit.

`tests/boundary/providers/godot/godotFileReal.test.ts` adds four lanes:

- `REA_VERIFY_GODOT3_BIN` runs a Godot 3 editor binary. Without a display,
  run the tests under `xvfb-run`. The binary builds and saves 28 binary
  resources and scenes (14 kinds, each plain and RSCC-compressed), then reads each back and
  writes what it sees: every stored property, every scene node and
  connection. Every value must match. The same script writes saves:
  - GCPF in all four compression modes, including FastLZ;
  - GDEC with a key and with a password;
  - plain `store_var`.

  Each save must decode to the plain save's bytes.

- `REA_VERIFY_GODOT3_SCRIPTS` points at a folder of `.gd` files. Godot 3
  compiles them and also exports them encrypted. Every token, and the line
  it is on, must match an independent lexing of the source, and every
  `.gde` must decrypt to the same tokens.
- `REA_VERIFY_GODOT_PCK_DIR` points at a folder of released games' packs.
  Every compiled script, binary resource, scene and `project.binary` in
  them must decode, with:
  - each resource read to the byte where the next begins;
  - scene arrays used exactly;
  - the rebuilt source lexing back to the same tokens on the same lines.
- `REA_VERIFY_GODOT4_PCK` and `REA_VERIFY_GODOT4_SOURCES` point at a
  Godot 4 game's pack and the source tree it was exported from. At least
  99% of the scripts must match their source token for token. In the rest,
  only string literals may differ, as when a build step writes a version
  string.

Results with Ubuntu's Godot 3.5.2:

- The generator lane passed with 170 property, node and connection
  comparisons.
- The scripts lane passed on the 288 scripts of `godot-demo-projects`
  (branch 3.5): 75,214 tokens.
- The pack lane passed on 12 itch.io games built with Godot 3.5 and 4.4 to
  4.7:
  - 919 compiled scripts: 17 in bytecode 13, 287 in tokenizer 100 and 615 in
    tokenizer 101;
  - 1,676 binary resources with 125,167 properties;
  - 714 scenes with 8,676 nodes.
- The Godot 4 lane passed on GDQuest's _Learn GDScript_ web build (Godot
  4.6.3) against the source at commit `edde160`, the commit the build
  names. 261 of 262 scripts matched exactly (110,972 tokens). The last
  differs only in the commit string its build step writes.

Not checked against a running engine:

- Godot 4's GDEC (AES-CFB) layout and Godot 4 `store_var` saves are
  checked only against fixtures written from the engine source. Godot 4
  `project.binary` files from the games above were read.
- FastLZ level 2 was not checked against real data. Godot compresses in
  4 KiB blocks, which FastLZ always writes at level 1.
