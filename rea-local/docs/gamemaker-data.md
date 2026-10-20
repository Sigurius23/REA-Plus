# GameMaker data files

`inspect_gamemaker_data` / `inspect-gamemaker-data` reads the data file a
GameMaker game ships its content in, for modding. It lists the chunks,
resources, bytecode entries, strings, functions and variables, texture pages
and embedded audio, the same file UndertaleModTool opens.

It reads:

| File              | Where it comes from                 |
| ----------------- | ----------------------------------- |
| `data.win`        | Windows                             |
| `game.unx`        | Linux                               |
| `game.droid`      | Android, inside the APK's `assets/` |
| `game.ios`        | iOS                                 |
| `audiogroupN.dat` | Audio groups                        |
| runner executable | A FORM appended to it               |

The bytecode is listed with its sizes, never run.

```sh
rea inspect-gamemaker-data ~/Games/gm/data.win --json
rea inspect-gamemaker-data ~/Games/gm/data.win --view resources --kind object --json
rea inspect-gamemaker-data ~/Games/gm/data.win --view code --query gml_Script_ --json
rea inspect-gamemaker-data ~/Games/gm/audiogroup1.dat --view audio --json
```

```json
{
  "name": "inspect_gamemaker_data",
  "arguments": {
    "path": "/games/gm/data.win",
    "view": "resources",
    "kind": "room"
  }
}
```

## What the result contains

- `file`: SHA-256, size, and the FORM's offset and size. A FORM appended to an
  executable is found by its GEN8 chunk.
- `general`, from GEN8 (null for an audio-group file):
  - name and display name, file name, config and game id;
  - bytecode version, VM or YYC, window size, flags such as `steam_enabled`
    and `borderless_window`, build time and Steam app id;
  - `stored_version`: GameMaker Studio 2 and later always store `2.0.0.0`;
  - `minimum_version`: the oldest runtime that can produce this chunk set,
    as UndertaleModTool detects it. `SEQN` means 2.3, `FEDS` 2.3.6, `FEAT`
    2022.8, `PSEM` 2023.2 and `UILR` 2024.13.
- `summary`: chunk count, resources per kind, and counts of code entries,
  strings, functions, variables, textures and audio.
- `page` and one view, filtered by `kind` and `query`:
  - `chunks`: each chunk's name, offset, size and pointer-list length.
  - `resources`: sounds, audio groups, sprites, backgrounds, paths, scripts,
    shaders, fonts, timelines, objects, rooms, extensions, texture groups,
    animation curves, sequences and particle systems, with names. Only
    fields at the same offsets in every version are included:
    - sprite: size and origin;
    - object: sprite;
    - room: caption, size, speed, persistence, creation-code entry and
      instance count;
    - script: code entry, and whether it is a 2.3 constructor;
    - sound: file, type, volume, pitch, audio group and audio entry;
    - font: display name;
    - extension: folder.
  - `code`: GML bytecode entries with length, locals, arguments and bytecode
    offset. Entries of 2.3 functions that share one body with their script
    are marked `shared`. YYC builds have none.
  - `strings`: the string table with each text's offset.
  - `symbols`: functions and variables with occurrence counts. Variables also
    show their instance type: self −1, other −2, all −3, global −5,
    local −7.
  - `textures`: texture pages as PNG, QOI or BZ2-compressed QOI, with
    dimensions and offset, or `external` when stored outside the file.
  - `audio`: embedded WAV and Ogg files with the default-group sounds that
    play them. Zero-filled placeholders are reported as `empty`.

Every string reference must land on a STRG entry. A misread layout therefore
fails with an input error instead of returning garbage.

## Boundaries

- Bytecode 13 to 17 (GameMaker Studio 1.4 to GameMaker 2024+) is supported.
  GameMaker 8 and earlier executables use another format and are refused.
- Bytecode is not disassembled or decompiled, and textures and audio are not
  extracted; use UndertaleModTool for that. Each entry's offset lets you cut
  it out yourself.
- Object parents, events and room layers move between versions and are not
  reported.
- Sounds in audio groups other than 0 play entries from that group's
  `audiogroupN.dat`.
- Files over 2 GiB are refused.

## Verification

`tests/boundary/providers/gamemaker/gameMakerData.test.ts` builds data files
in source with UndertaleModTool's layouts:

- a bytecode 17 game with sounds, a sprite, scripts (one a 2.3
  constructor), objects, a room with instances, a sequence, code entries
  sharing a body, functions, variables, a PNG, a QOI and an external texture,
  and WAV and Ogg audio;
- a bytecode 14 game;
- a YYC build;
- the same game appended to an executable;
- an audio-group file;
- a file whose sprite name points into the middle of a string, which is
  refused.

`REA_VERIFY_GAMEMAKER_DIR`, pointed at extracted game files, checks every
`data.win`, `game.droid` and `audiogroupN.dat` under it:

- the chunks tile the FORM exactly;
- bytecode lies inside CODE;
- every texture and audio entry has a known format;
- sounds name audio entries that exist.

Together with the strict string references, this ran on 21 files from 18 free
games on itch.io:

- 15 Windows builds and 3 Android builds, plus 3 audio-group files;
- bytecode 16 and 17, with chunk sets from GameMaker Studio 2 up to 2024.13;
- among them Nuclear Throne for Android, the DELTARUNE chapter select and
  Spelunky Classic HD.

UndertaleModTool's source was the format reference. The tool itself was not
run here, so names and fields have not been compared with its output.
