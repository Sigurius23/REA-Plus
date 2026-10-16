# RPG Maker MV and MZ games

`inspect_rpgmaker_project` / `inspect-rpgmaker-project` reads an RPG Maker
MV or MZ game folder for modding, translation or save editing. It covers
maps and their events, dialogue, switches and variables, the database,
plugins, encrypted assets and save files.

MV and MZ games store their data as JSON the editor writes. REA+ reads that
JSON and parses `js/plugins.js` as the editor's plugin list. Nothing in the
game is run: no core script, plugin or event script.

```sh
rea inspect-rpgmaker-project ~/Games/MyRpg --json
rea inspect-rpgmaker-project ~/Games/MyRpg --view dialogue --map 3 --json
rea inspect-rpgmaker-project ~/Games/MyRpg --view switches --query boss --json
rea inspect-rpgmaker-project ~/Games/MyRpg --view assets --asset img/faces/Actor1.png_ --json
rea inspect-rpgmaker-project ~/Games/MyRpg --view saves --json
```

```json
{
  "name": "inspect_rpgmaker_project",
  "arguments": { "path": "/games/my-rpg", "view": "database", "table": "items" }
}
```

`path` is the folder holding `data/System.json`. That is the game root for
MZ and for MV editor projects. For a deployed MV game it is the folder
holding `www/`, or `www/` itself. Reported paths are relative to the folder
you select.

## What the result contains

- `project`:
  - the engine (`mv` or `mz`), where its data was found, and the version in
    the `rpg_core.js` / `rmmz_core.js` header;
  - the title, locale, `versionId` and start position;
  - `data_sha256`, a digest over every data file read.
- `encryption`:
  - whether images and audio are encrypted, and the `encryptionKey` from
    System.json;
  - whether that key is the MD5 of an empty passphrase;
  - a key recovered from an encrypted PNG, and whether the two match.
    The first 16 bytes of every PNG are fixed, so one encrypted image gives
    the whole key even when System.json has been altered.
- `summary`: counts of maps, events, common events, troops, messages,
  choices, named switches and variables, database entries per table,
  plugins (enabled, missing script files), assets (encrypted, plain,
  undecryptable) and saves.
- `page` and one view, filtered by `map`, `table` and `query`:
  - `maps`: MapInfos name and display name, parent, size, tileset, BGM,
    events, pages and commands. Also message and choice counts, the maps
    Transfer Player reaches, and the common events it calls.
  - `dialogue`: Show Text with its MZ name box and face, Show Choices,
    Show Scrolling Text and comments. Each row gives its map event, page
    and command index, or the common event or troop it is in. Text is
    reported as written, escape codes such as `\N[1]` and `\C[2]` kept.
  - `switches`: named or referenced switches and variables, with up to 20
    read and write sites each. Sites come from Control Switches/Variables,
    Conditional Branch, Input Number, Select Item, Get Location Info,
    Transfer Player by variables, event page and troop page conditions, and
    common-event triggers.
  - `database`: actors, classes, skills, items, weapons, armors, enemies,
    troops, states, animations, tilesets and common events. Each entry has
    its description, note, notetag names and other scalar fields.
  - `plugins`: each `plugins.js` entry with its status, description,
    parameters, and its script's size and SHA-256 (or `present: false`).
  - `assets`: files under `img/`, `audio/` and `movies/`. Each encrypted file
    (`.rpgmvp`/`.rpgmvo`/`.rpgmvm` on MV, `.png_`/`.ogg_`/`.m4a_` on MZ) has
    its header checked and its file type found after decryption. With
    `asset`, that one file is decrypted fully, giving its digest and PNG size.
  - `saves`: `save/` files decoded as the engine does: LZString base64 for MV
    `.rpgsave`, zlib for MZ `.rmmzsave`. Each game save gives its version id,
    save time (from the global save), playtime, map and position, gold and
    steps. It also lists the party (level, HP, MP), items, weapons and armors
    with database names, switches that are on, non-zero variables with their
    System.json names, and the count of self switches set.

## Boundaries

- RPG Maker XP, VX and VX Ace store Ruby Marshal data in `.rxdata` /
  `.rvdata2` files, usually inside an `.rgss3a` archive. They are not read.
- Games packed into an executable (Enigma Virtual Box, a renamed
  `package.nw`), or whose data a plugin encrypts, must be unpacked first.
- Plugins can change how text codes, saves and data behave. REA+ reports the
  data as the core engine stores it.
- Sites from Script commands and plugin commands are not interpreted.
- Data files over 64 MiB, more than 768 MiB of data in total, and asset
  folders over 200,000 files are refused or truncated. A selected asset may
  be up to 512 MiB. Symlinks in place of data files are refused. Symlinks in
  asset and save folders are skipped and counted.

## Verification

`tests/boundary/providers/rpgmaker/rpgMakerProject.test.ts` builds a deployed
MV game and an MZ game in source. Each has maps, events, a common event, a
troop, the database and `plugins.js`. Its assets are encrypted with the
deploy step's scheme, plus one damaged file. Its saves are in each
generation's format. The MV saves use the same LZString 1.3 base64 that MV
bundles: re-compressing a save written by a real MV engine gives identical
text. The test also checks refusals:

- a folder that is not a game;
- asset paths that escape the game folder;
- a symlinked map file;
- a `plugins.js` holding code instead of the editor's list, which is
  rejected without being run.

`tests/boundary/providers/rpgmaker/rpgMakerEngine.test.ts` runs real games.
Point `REA_VERIFY_RPGMAKER_GAMES` at a folder of deployed games and
`REA_VERIFY_CHROMIUM` at a Chromium binary. Each game is served on
loopback, and its own engine runs in headless Chromium. The test compares:

- engine name, encryption key and map list with REA+;
- up to six encrypted assets decrypted by the engine
  (`Decrypter.decryptArrayBuffer` or `Utils.decryptArrayBuffer`), by digest
  and decoded image size;
- a save: the engine starts a new game, changes gold, an item, a switch and
  two variables, and saves through its own `StorageManager`. The files are
  written as NW.js would write them, and REA+ must report the engine's gold,
  party, items, switches, variables, map, version id, playtime and save time.

Nine game folders passed: four MV (one with an empty passphrase, one
unencrypted, one with a pre-title-map plugin) and four MZ (one unencrypted
and plugin-heavy, one with an empty passphrase), plus one MV game laid out
under `www/`. All are free HTML5 builds published on itch.io. They span MV
1.6 and MZ 1.6 to 1.9, in English and Japanese.
