/**
 * Token tables of compiled GDScript, from Godot's gdscript_tokenizer.h and
 * gdscript_functions.h at each release. Each entry is the enum name and the
 * source text; names without text are identifiers, literals, layout tokens
 * or built-ins resolved from the token's value.
 */

export interface TokenKind {
  readonly name: string;
  readonly text: string | null;
}

const kinds = (spec: string): readonly TokenKind[] =>
  spec
    .trim()
    .split(/\s+/u)
    .map((entry) => {
      // Split at the first "=" only: OP_EQUAL=== is OP_EQUAL with text "==".
      const at = entry.indexOf("=");
      return at < 0
        ? { name: entry, text: null }
        : { name: entry.slice(0, at), text: entry.slice(at + 1) };
    });

/** Godot 3.1 to 3.6 (bytecode 13). */
const GODOT3 = `
EMPTY= IDENTIFIER CONSTANT SELF=self BUILT_IN_TYPE BUILT_IN_FUNC OP_IN=in
OP_EQUAL=== OP_NOT_EQUAL=!= OP_LESS=< OP_LESS_EQUAL=<= OP_GREATER=> OP_GREATER_EQUAL=>=
OP_AND=and OP_OR=or OP_NOT=not OP_ADD=+ OP_SUB=- OP_MUL=* OP_DIV=/ OP_MOD=%
OP_SHIFT_LEFT=<< OP_SHIFT_RIGHT=>> OP_ASSIGN== OP_ASSIGN_ADD=+= OP_ASSIGN_SUB=-=
OP_ASSIGN_MUL=*= OP_ASSIGN_DIV=/= OP_ASSIGN_MOD=%= OP_ASSIGN_SHIFT_LEFT=<<=
OP_ASSIGN_SHIFT_RIGHT=>>= OP_ASSIGN_BIT_AND=&= OP_ASSIGN_BIT_OR=|= OP_ASSIGN_BIT_XOR=^=
OP_BIT_AND=& OP_BIT_OR=| OP_BIT_XOR=^ OP_BIT_INVERT=~
CF_IF=if CF_ELIF=elif CF_ELSE=else CF_FOR=for CF_WHILE=while CF_BREAK=break
CF_CONTINUE=continue CF_PASS=pass CF_RETURN=return CF_MATCH=match
PR_FUNCTION=func PR_CLASS=class PR_CLASS_NAME=class_name PR_EXTENDS=extends PR_IS=is
PR_ONREADY=onready PR_TOOL=tool PR_STATIC=static PR_EXPORT=export PR_SETGET=setget
PR_CONST=const PR_VAR=var PR_AS=as PR_VOID=void PR_ENUM=enum PR_PRELOAD=preload
PR_ASSERT=assert PR_YIELD=yield PR_SIGNAL=signal PR_BREAKPOINT=breakpoint
PR_REMOTE=remote PR_SYNC=sync PR_MASTER=master PR_SLAVE=slave PR_PUPPET=puppet
PR_REMOTESYNC=remotesync PR_MASTERSYNC=mastersync PR_PUPPETSYNC=puppetsync
BRACKET_OPEN=[ BRACKET_CLOSE=] CURLY_BRACKET_OPEN={ CURLY_BRACKET_CLOSE=}
PARENTHESIS_OPEN=( PARENTHESIS_CLOSE=) COMMA=, SEMICOLON=; PERIOD=. QUESTION_MARK=?
COLON=: DOLLAR=$ FORWARD_ARROW=-> NEWLINE CONST_PI=PI CONST_TAU=TAU WILDCARD=_
CONST_INF=INF CONST_NAN=NAN ERROR EOF CURSOR`;

/** Godot 3.0 (bytecode 12) had do/switch/case and lacked later keywords. */
const godot30 = (): readonly TokenKind[] => {
  const removed = new Set([
    "PR_CLASS_NAME",
    "PR_AS",
    "PR_VOID",
    "PR_PUPPET",
    "PR_REMOTESYNC",
    "PR_MASTERSYNC",
    "PR_PUPPETSYNC",
    "FORWARD_ARROW",
  ]);
  return kinds(GODOT3).flatMap((kind) => {
    if (removed.has(kind.name)) return [];
    if (kind.name === "CF_FOR") return [kind, { name: "CF_DO", text: "do" }];
    if (kind.name === "CF_WHILE")
      return [
        kind,
        { name: "CF_SWITCH", text: "switch" },
        { name: "CF_CASE", text: "case" },
      ];
    return [kind];
  });
};

/** Godot 4.5 and later (tokenizer 101); 4.3 and 4.4 (100) lack "...". */
const GODOT4 = `
EMPTY= ANNOTATION IDENTIFIER LITERAL LESS=< LESS_EQUAL=<= GREATER=> GREATER_EQUAL=>=
EQUAL_EQUAL=== BANG_EQUAL=!= AND=and OR=or NOT=not AMPERSAND_AMPERSAND=&& PIPE_PIPE=||
BANG=! AMPERSAND=& PIPE=| TILDE=~ CARET=^ LESS_LESS=<< GREATER_GREATER=>> PLUS=+
MINUS=- STAR=* STAR_STAR=** SLASH=/ PERCENT=% EQUAL== PLUS_EQUAL=+= MINUS_EQUAL=-=
STAR_EQUAL=*= STAR_STAR_EQUAL=**= SLASH_EQUAL=/= PERCENT_EQUAL=%= LESS_LESS_EQUAL=<<=
GREATER_GREATER_EQUAL=>>= AMPERSAND_EQUAL=&= PIPE_EQUAL=|= CARET_EQUAL=^=
IF=if ELIF=elif ELSE=else FOR=for WHILE=while BREAK=break CONTINUE=continue PASS=pass
RETURN=return MATCH=match WHEN=when AS=as ASSERT=assert AWAIT=await
BREAKPOINT=breakpoint CLASS=class CLASS_NAME=class_name CONST=const ENUM=enum
EXTENDS=extends FUNC=func IN=in IS=is NAMESPACE=namespace PRELOAD=preload SELF=self
SIGNAL=signal STATIC=static SUPER=super TRAIT=trait VAR=var VOID=void YIELD=yield
BRACKET_OPEN=[ BRACKET_CLOSE=] BRACE_OPEN={ BRACE_CLOSE=} PARENTHESIS_OPEN=(
PARENTHESIS_CLOSE=) COMMA=, SEMICOLON=; PERIOD=. PERIOD_PERIOD=.. PERIOD_PERIOD_PERIOD=...
COLON=: DOLLAR=$ FORWARD_ARROW=-> UNDERSCORE=_ NEWLINE INDENT DEDENT CONST_PI=PI
CONST_TAU=TAU CONST_INF=INF CONST_NAN=NAN VCS_CONFLICT_MARKER BACKTICK=\` QUESTION_MARK=?
ERROR EOF`;

/** Built-in functions of Godot 3.2 to 3.6 in enum order (3.5 appended deep_equal). */
const FUNCTIONS32 = `sin cos tan sinh cosh tanh asin acos atan atan2 sqrt fmod fposmod
posmod floor ceil round abs sign pow log exp is_nan is_inf is_equal_approx is_zero_approx
ease decimals step_decimals stepify lerp lerp_angle inverse_lerp range_lerp smoothstep
move_toward dectime randomize randi randf rand_range seed rand_seed deg2rad rad2deg
linear2db db2linear polar2cartesian cartesian2polar wrapi wrapf max min clamp
nearest_po2 weakref funcref convert typeof type_exists char ord str print printt prints
printerr printraw print_debug push_error push_warning var2str str2var var2bytes
bytes2var range load inst2dict dict2inst validate_json parse_json to_json hash Color8
ColorN print_stack get_stack instance_from_id len is_instance_valid deep_equal`;

/** Godot 3.1 lacked functions 3.2 inserted mid-table; 3.0 also lacked 3.1's. */
const ADDED_IN_32 = new Set([
  "posmod",
  "is_equal_approx",
  "is_zero_approx",
  "step_decimals",
  "lerp_angle",
  "smoothstep",
  "move_toward",
  "ord",
  "deep_equal",
]);
const ADDED_IN_31 = new Set([
  "print_debug",
  "push_error",
  "push_warning",
  "get_stack",
  "is_instance_valid",
]);

const functions = (engine: "3.0" | "3.1" | "3.2"): readonly string[] =>
  FUNCTIONS32.trim()
    .split(/\s+/u)
    .filter(
      (name) =>
        engine === "3.2" ||
        (!ADDED_IN_32.has(name) &&
          (engine === "3.1" || !ADDED_IN_31.has(name))),
    );

/** Godot 3 Variant types, the value of a BUILT_IN_TYPE token. */
export const GODOT3_TYPES =
  `Nil bool int float String Vector2 Rect2 Vector3 Transform2D
Plane Quat AABB Basis Transform Color NodePath RID Object Dictionary Array PoolByteArray
PoolIntArray PoolRealArray PoolStringArray PoolVector2Array PoolVector3Array PoolColorArray`
    .trim()
    .split(/\s+/u);

export interface ScriptFormat {
  readonly version: number;
  readonly engine: string;
  readonly tokens: readonly TokenKind[];
  readonly functions: readonly string[];
}

/** The token and built-in tables for each compiled-script version. */
export const SCRIPT_FORMATS: Readonly<Record<number, ScriptFormat>> = {
  12: {
    version: 12,
    engine: "3.0",
    tokens: godot30(),
    functions: functions("3.0"),
  },
  13: {
    version: 13,
    engine: "3.1-3.6",
    tokens: kinds(GODOT3),
    functions: functions("3.2"),
  },
  100: {
    version: 100,
    engine: "4.3-4.4",
    tokens: kinds(GODOT4).filter(({ name }) => name !== "PERIOD_PERIOD_PERIOD"),
    functions: [],
  },
  101: { version: 101, engine: "4.5+", tokens: kinds(GODOT4), functions: [] },
};
