# Compiled Ren'Py scripts

`inspect_renpy_script` / `inspect-renpy-script` reads a compiled Ren'Py script
(`.rpyc`), the form most visual novels ship their story in, and maps it for
modding or translation: labels and how they branch, every line of dialogue
with its speaker and translation identifier, menus with their choices and
targets, definitions, and existing translations.

A `.rpyc` is a zlib-compressed Python pickle of Ren'Py's syntax tree.
Unpickling it normally imports Ren'Py and can run arbitrary code. REA+
decodes the pickle itself: classes under `renpy.*` and `store.*` become inert
records of their constructor arguments and state, nothing is imported or
called, and any other class (`os.system`, `subprocess`, …) is refused.

```sh
rea inspect-renpy-script ~/Games/vn/game/script.rpyc --json
rea inspect-renpy-script ~/Games/vn/game/script.rpyc --view dialogue --label chapter2 --json
rea inspect-renpy-script ~/Games/vn/game/script.rpyc --view menus --json
rea inspect-renpy-script ~/Games/vn/game/tl/french/script.rpyc --view translations --json
```

```json
{
  "name": "inspect_renpy_script",
  "arguments": {
    "path": "/games/vn/game/script.rpyc",
    "view": "dialogue",
    "query": "the book"
  }
}
```

Scripts packed in an `.rpa` archive can be found with
[`inspect_game_archive`](./game-archives.md), which previews entries without
extracting them.

## What the result contains

- `script`: path, SHA-256, size, container format (`rpyc2` for the
  `RENPY RPC2` slot format of Ren'Py 6.18+, `rpyc1` for older zlib-only
  files), the slot read, Ren'Py's script version, the `.rpy` source files the
  statements came from, and statement counts by kind.
- `summary`: label, dialogue, menu, definition and translation counts, the
  translation languages present, and the speakers with the most lines.
- `page` and one view, filtered by `label` (dialogue and menus) and `query`:
  - `labels`: name, source line, statements, dialogue lines and menus inside,
    and the labels it jumps to and calls (`expression …` when the target is
    computed).
  - `dialogue`: label, source file and line, speaker as written (a character
    variable such as `e`, or null for narration), text as written (text tags
    and `{{`/`%%` escapes kept), the translation identifier and the language
    (null for the original script). The identifier is the one
    `translate <language> <identifier>:` blocks use, so a translator can tie
    each line to its translation.
  - `menus`: caption, and each choice's text, condition and the jumps and
    calls at the start of its block.
  - `definitions`: `define` and `default` names with their Python values,
    `image` names with their values, and `screen`, `transform` and `style`
    names.
  - `translations`: `translate <language> <identifier>` blocks and
    `translate <language> strings` entries with old and new text.

Ren'Py 8 writes each script twice. Slot 1 is the parsed script, and slot 2 is
the same script after its static transforms, where dialogue carries its
translation identifier. REA+ reads slot 2 when present, as Ren'Py itself
does.

## Boundaries

- Screen language, ATL and Python blocks are counted and named, not
  decompiled back to source; use a decompiler such as unrpyc when you need the
  full `.rpy`.
- Text is reported exactly as stored. Ren'Py's own `dialogue` export
  un-doubles `{{` and `%%`, escapes tabs and newlines, and labels `extend`
  lines with the previous speaker; REA+ leaves that to the caller.
- Scripts over 256 MiB are refused.

## Verification

`tests/boundary/providers/renpy/renpyScript.test.ts` builds a script in
source: a protocol-2 pickle of slotted `renpy.ast` nodes in the `RENPY RPC2`
container (slots 1 and 2, slot 1 only, and the zlib-only form), plus a
script whose pickle names `os.system`, which is refused. Python's own
unpickler loads the same fixtures. `src/gamearchives/SafePickle.test.ts`
decodes pickles written by Python 3.13 at protocols 2 and 5.

`REA_VERIFY_RENPY_SDK`, pointed at the Ren'Py 8.5.3 SDK, decodes every one
of the 585 `.rpyc` files the SDK ships: the launcher, the common library, the tutorial and The Question,
with translations in 23 languages. It then runs
the SDK's own `renpy.sh <game> dialogue None` for The Question and the
tutorial and compares every row. All 894 identifiers, speakers, texts,
files and line numbers matched once Ren'Py's output transforms were applied.
During development, label sets were also compared with the `label`
statements in the 581 `.rpy` sources beside the compiled files. They agreed
except where the source pattern itself misfired: `init label`, named
`menu`s (which compile to labels), screen-language `label` displayables, and
a `define` inside a docstring.
