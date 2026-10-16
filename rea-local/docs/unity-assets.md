# Unity asset bundles and serialized files

`inspect_unity_assets` / `inspect-unity-assets` reads Unity's own asset
containers: UnityFS asset bundles (`.bundle`, `.ab`, `.unity3d`, Addressables
output, a game's `StreamingAssets` downloads) and the serialized files a player
build ships in `<Game>_Data` (`level0`, `sharedassets0.assets`,
`resources.assets`, `globalgamemanagers`, `globalgamemanagers.assets`). It
answers the first questions a modder asks of a Unity game: which objects a
file holds and what they are called, which asset path or `Resources.Load` path
maps to which object, and which MonoBehaviour scripts a scene or bundle uses.

REA+ decodes the containers natively, LZ4, LZ4HC and LZMA blocks included. It
needs no tool configuration and never loads anything into Unity.

```sh
rea inspect-unity-assets ~/Game/Game_Data/StreamingAssets/ui_atlas.bundle --view container --json
rea inspect-unity-assets ~/Game/Game_Data/level1 --class_name MonoBehaviour --json
rea inspect-unity-assets ~/Game/Game_Data/globalgamemanagers.assets --view scripts --query Player --json
```

```json
{
  "name": "inspect_unity_assets",
  "arguments": {
    "path": "/game/Game_Data/level1",
    "view": "objects",
    "class_name": "GameObject",
    "query": "door"
  }
}
```

## What the result contains

Every call returns the file summary and one paged view.

- `file`: path, SHA-256, size, and whether it is a UnityFS bundle or a bare
  serialized file.
- `bundle` (UnityFS only): format version, player version and engine
  revision, header flags, the block table's compression and position, block
  counts by compression method, and every directory node with its offset,
  size, flags and kind (`serialized_file`, `resource` for `.resS`/`.resource`
  payloads, or `other`). `decoded_bytes` is how much block data REA+ actually
  decompressed; blocks are decoded on demand, so large `.resS` payloads are
  usually skipped.
- `serialized_files`: for each serialized file, its format version, Unity
  version, target platform, byte order, whether it carries type trees, its
  types with object counts, its external file references (with Unity GUIDs in
  `.meta` order, so `0000000000000000e000000000000000` is `unity default
  resources`), and `names`: how many objects REA+ read fields from, how many
  belong to classes it cannot read without a type tree, and how many failed to
  decode.
- `classes`: object counts per class across the input.
- `dependencies`: an AssetBundle's `m_Dependencies`, the other bundles it needs
  loaded.
- `page`: the view, filters, offset, limit and the number of matching entries.

### Views

- `objects` (default): each object's file, path ID (signed 64-bit, as decimal
  text), class, byte offset and size, `m_Name`, the owning GameObject of a
  component (path ID and name), and a MonoBehaviour's `m_Script` reference.
  When the MonoScript is in the same file or another serialized file of the
  same bundle, the script carries its class name, namespace and assembly;
  otherwise it names the external file (usually `globalgamemanagers.assets`).
- `container`: asset paths. For bundles these are the AssetBundle's
  `m_Container` entries (`assets/characters/hero.prefab` and so on) with
  preload ranges; for `globalgamemanagers` they are the ResourceManager's
  `Resources.Load` paths. Each entry resolves to its object's class and name
  when the object is in the input, or names the external file holding it.
- `scripts`: MonoScripts (class name, namespace, assembly) and, for each, how
  many MonoBehaviours in the input use it. Scripts referenced from another
  file appear with `local: false` and that file's path; open that file (for a
  player build, `globalgamemanagers.assets`) to read their names.

`class_name` keeps one class (case-insensitive) in the objects and container
views. `query` is a case-insensitive substring match on object, owner and
script names, asset paths, or script class, namespace and assembly.

## Type trees

Asset bundles normally embed type trees: per-class field layouts that let any
reader walk an object. REA+ uses them to step over fields and read only what
it reports, stopping at the last field it needs. Player builds usually omit
type trees. For those files REA+ reads names, owners, scripts and containers
from the stable start of a few class layouts: NamedObject subclasses (textures,
meshes, materials, shaders, audio, sprites, text assets, animation clips and
similar), GameObject, common components (Transform, renderers, colliders,
lights, cameras, UI), MonoBehaviour, MonoScript, AssetBundle and
ResourceManager. Objects of other classes count as `unread`; their class,
offset and size are still reported.

## Boundaries

- UnityFS bundles of format 6 to 8 are read; format 9 follows UnityPy's block
  layout and has not been checked against a real file. UnityWeb and UnityRaw
  bundles (Unity 5.2 and earlier), UnityCN-encrypted bundles and LZHAM blocks
  are refused.
- Serialized files of formats 9 to 22 are read (Unity 5 through Unity 6.0).
  Formats 23 and later, which store type trees differently, are refused. Only
  formats 17 and 22 have been checked against real files; the pre-blob type
  trees of formats 9 and 11 are parsed but unverified.
- Asset payloads (texture pixels, meshes, audio, MonoBehaviour script fields)
  are not decoded, and nothing is extracted or written back.
- Fields after a `[SerializeReference]` registry cannot be stepped over; such
  objects report `failed` if a wanted field lies past it.
- Files up to 2 GiB are read into memory; LZMA blocks decode into memory, up
  to 1 GiB per block.

## Verification

`tests/boundary/providers/unity/unityAssets.test.ts` builds files in source: a
Unity 2022.3 standalone scene without type trees, and a 2019.4 Android bundle
with type trees wrapped in UnityFS uncompressed, as multi-block LZ4, as LZMA
with the block table at the end, as format 6 and 7, and with a big-endian
serialized file. UnityPy 1.25.4 reads the same fixtures to the same names,
scripts, owners and containers. `src/unity/UnityCompression.test.ts` checks
the decoders against an xz-produced LZMA stream; during development they also
decoded 20 LZMA streams from Python's `lzma` and 40 LZ4 blocks from
`python-lz4`, fast and high-compression, byte for byte.

Two real-data lanes compare REA+ with UnityPy 1.25.4:

- `REA_VERIFY_UNITY_SAMPLES_DIR`: UnityPy's sample bundles (`tests/samples`,
  fetched through Git LFS). Four Unity 5.6 to 2018.4 Android bundles with
  LZ4HC blocks: object counts, AssetBundle names and container entries.
- `REA_VERIFY_UNITY_PLAYER_DIR`: `Startup_Data` from Unity ML-Agents' 1.1.0
  Linux test build (Unity 2022.3.4f1, format 22, no type trees): a 6351-object
  scene, MonoBehaviour owners and script references, 99 ResourceManager paths
  and 1220 MonoScripts.

On those 12 files (12,103 objects), plus the samples repacked by UnityPy as
LZMA, LZ4 and uncompressed bundles, REA+ agreed with UnityPy on every
object's path ID, class, offset and size. It also agreed on all 5,268 names
UnityPy reports, 7,947 component owners, 1,155 MonoBehaviour script
references, 1,236 MonoScripts, 48 AssetBundle container entries and 99
Resources paths, with no disagreements.
