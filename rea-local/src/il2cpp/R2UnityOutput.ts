import { z } from "zod";

import type {
  Il2CppAssembly,
  Il2CppClass,
  Il2CppInterop,
  Il2CppStringLiteral,
} from "../domain/il2cpp/il2cppMetadata.js";

/** r2unity CLI output that does not match the 1.2 shapes this adapter admits. */
export class R2UnityOutputDrift extends Error {}

const uint = z.number().int().nonnegative();
const hex8 = z.string().regex(/^0x[0-9a-f]{8}$/u);
const hex4 = z.string().regex(/^0x[0-9a-f]{4}$/u);
const nullableString = z.string().nullable();

/** `-c -j` (with `-f` for native pointers), recorded from r2unity 1.2.8. */
const classesOutputSchema = z.strictObject({
  ok: z.literal(true),
  version: z.number().int().positive(),
  unity_range: z.string(),
  has_ptrs: z.boolean(),
  native_source: z.enum(["none", "symbol", "override", "heuristic"]),
  code_registration: uint,
  metadata_registration: uint,
  method_pointers: uint,
  code_gen_modules: uint,
  native_tables: z.record(
    z.string(),
    z.strictObject({ count: uint, va: uint }),
  ),
  types: uint,
  methods: uint,
  fields: uint,
  classes: z.array(
    z.strictObject({
      index: uint,
      name: nullableString,
      namespace: nullableString,
      short_name: nullableString,
      base: nullableString,
      base_type_index: z.number().int(),
      flags: hex8,
      token: hex8,
      interfaces: z.array(
        z.strictObject({ type_index: z.number().int(), name: nullableString }),
      ),
      fields: z.array(
        z.strictObject({
          index: uint,
          name: nullableString,
          type_index: z.number().int(),
          type: nullableString,
          token: hex8,
        }),
      ),
      methods: z.array(
        z.strictObject({
          index: uint,
          name: nullableString,
          full_name: nullableString,
          parameter_count: uint,
          addr: uint,
          token: hex8,
          flags: hex4,
          iflags: hex4,
          attrs: nullableString,
        }),
      ),
    }),
  ),
});

const interopEntry = {
  image: z.string(),
  method: z.string(),
  token: hex8,
  flags: hex4,
  iflags: hex4,
  confidence: z.number().int().min(0).max(100),
};

const pinvokesOutputSchema = z.strictObject({
  ok: z.literal(true),
  version: z.number().int().positive(),
  pinvokes: z.array(
    z.strictObject({
      ...interopEntry,
      dll: nullableString,
      entry: nullableString,
    }),
  ),
  // 1.2.8 always emits these placeholders with -P.
  reverse_pinvokes: z.array(z.never()).max(0),
  anonymous_reverse_pinvokes: z.array(z.never()).max(0),
  interop_data: z.null(),
});

const reversePinvokesOutputSchema = z.strictObject({
  ok: z.literal(true),
  version: z.number().int().positive(),
  reverse_pinvokes: z.array(
    z.strictObject({
      ...interopEntry,
      attribute: z.enum([
        "MonoPInvokeCallback",
        "UnmanagedCallersOnly",
        "reverse",
      ]),
      wrapper_va: z
        .string()
        .regex(/^0x[0-9a-f]{1,16}$/u)
        .optional(),
      wrapper_index: uint.optional(),
    }),
  ),
});

const property = z.strictObject({ name: z.string(), value: z.string() });

/** `-S -j`: CycloneDX 1.5 with one library component per managed assembly. */
const sbomOutputSchema = z.strictObject({
  bomFormat: z.literal("CycloneDX"),
  specVersion: z.literal("1.5"),
  version: z.literal(1),
  metadata: z.strictObject({
    tools: z.strictObject({
      components: z.array(
        z.strictObject({ type: z.literal("application"), name: z.string() }),
      ),
    }),
    component: z.strictObject({
      type: z.literal("application"),
      name: z.string(),
      version: z.string(),
      properties: z.array(property),
    }),
  }),
  components: z.array(
    z.strictObject({
      "bom-ref": z.string(),
      type: z.literal("library"),
      name: z.string(),
      version: z.string(),
      purl: z.string(),
      properties: z.array(property),
    }),
  ),
  dependencies: z.array(
    z.strictObject({ ref: z.string(), dependsOn: z.array(z.string()) }),
  ),
});

const parseJson = <T>(
  schema: z.ZodType<T>,
  command: string,
  stdout: string,
): T => {
  let value: unknown;
  try {
    value = JSON.parse(stdout);
  } catch (cause: unknown) {
    throw new R2UnityOutputDrift(`r2unity ${command} did not print JSON.`, {
      cause,
    });
  }
  const parsed = schema.safeParse(value);
  if (!parsed.success)
    throw new R2UnityOutputDrift(
      `r2unity ${command} printed JSON outside the admitted 1.2 shape: ${parsed.error.issues
        .slice(0, 3)
        .map((issue) => `${issue.path.join(".")}: ${issue.message}`)
        .join("; ")}`,
      { cause: parsed.error },
    );
  return parsed.data;
};

const hexAddress = (value: number): string | null =>
  value === 0 ? null : `0x${value.toString(16)}`;

export interface R2UnityClassInventory {
  readonly wireVersion: number;
  readonly unityRange: string | null;
  readonly counts: {
    readonly types: number;
    readonly methods: number;
    readonly fields: number;
  };
  readonly native: {
    readonly method_addresses_recovered: boolean;
    readonly source: "symbol" | "override" | "heuristic" | "none";
    readonly code_registration: string | null;
    readonly metadata_registration: string | null;
    readonly method_pointers: string | null;
    readonly code_gen_modules: string | null;
    readonly tables: readonly {
      readonly name: string;
      readonly address: string;
      readonly count: number;
    }[];
  };
  readonly classes: readonly Il2CppClass[];
}

/** Normalize `-c -j`; zero addresses mean r2unity recovered nothing. */
export const parseR2UnityClasses = (stdout: string): R2UnityClassInventory => {
  const output = parseJson(classesOutputSchema, "-c -j", stdout);
  const classes = output.classes.map((type): Il2CppClass => ({
    index: type.index,
    name: type.name,
    namespace: type.namespace,
    short_name: type.short_name,
    base: type.base,
    base_type_index: type.base_type_index < 0 ? null : type.base_type_index,
    flags: type.flags,
    token: type.token,
    interfaces: type.interfaces,
    field_count: type.fields.length,
    method_count: type.methods.length,
    member_scope: "all",
    fields: type.fields,
    methods: type.methods.map(({ addr, attrs, ...method }) => ({
      ...method,
      address: output.has_ptrs ? hexAddress(addr) : null,
      attributes: attrs,
    })),
  }));
  return {
    wireVersion: output.version,
    unityRange: output.unity_range === "unknown" ? null : output.unity_range,
    counts: {
      types: output.types,
      methods: output.methods,
      fields: output.fields,
    },
    native: {
      method_addresses_recovered: output.has_ptrs,
      source: output.native_source,
      code_registration: hexAddress(output.code_registration),
      metadata_registration: hexAddress(output.metadata_registration),
      method_pointers: hexAddress(output.method_pointers),
      code_gen_modules: hexAddress(output.code_gen_modules),
      tables: Object.entries(output.native_tables).flatMap(([name, table]) => {
        const at = hexAddress(table.va);
        return at === null ? [] : [{ name, address: at, count: table.count }];
      }),
    },
    classes,
  };
};

const LITERAL_LINE =
  /^(?<index>\d+)\t0x(?<offset>[0-9a-f]{1,8})\t(?<bytes>\d+)\t(?:"(?<text>.*)"|(?<invalid><invalid>))$/su;
const SIMPLE_ESCAPES: Readonly<Record<string, number>> = {
  "\\": 0x5c,
  '"': 0x22,
  n: 0x0a,
  r: 0x0d,
  t: 0x09,
};

/** Undo r2unity's literal rendering: \\ \" \n \r \t and \xHH for other bytes. */
export const unescapeR2UnityLiteral = (rendered: string): Buffer => {
  const bytes: Buffer[] = [];
  let plain = "";
  const flush = () => {
    if (plain.length > 0) bytes.push(Buffer.from(plain, "utf8"));
    plain = "";
  };
  for (let index = 0; index < rendered.length; index += 1) {
    const character = rendered[index] ?? "";
    if (character === '"')
      throw new R2UnityOutputDrift("r2unity -z printed an unescaped quote.");
    if (character !== "\\") {
      plain += character;
      continue;
    }
    flush();
    const next = rendered[index + 1] ?? "";
    const simple = SIMPLE_ESCAPES[next];
    if (simple !== undefined) {
      bytes.push(Buffer.from([simple]));
      index += 1;
      continue;
    }
    const hex = rendered.slice(index + 2, index + 4);
    if (next !== "x" || !/^[0-9a-f]{2}$/u.test(hex))
      throw new R2UnityOutputDrift(
        `r2unity -z printed an unknown escape \\${next}.`,
      );
    bytes.push(Buffer.from(hex, "hex"));
    index += 3;
  }
  flush();
  return Buffer.concat(bytes);
};

const UTF8 = new TextDecoder("utf-8", { fatal: true });
const LOSSY_UTF8 = new TextDecoder("utf-8");

/**
 * Normalize `-q -z` against the metadata bytes. r2unity's rendering must
 * decode to exactly the bytes at its reported offset, so offsets and lengths
 * are cross-checked rather than trusted.
 */
export const parseR2UnityStringLiterals = (
  stdout: string,
  metadata: Buffer,
): Il2CppStringLiteral[] => {
  if (stdout.length > 0 && !stdout.endsWith("\n"))
    throw new R2UnityOutputDrift("r2unity -z output ended mid-line.");
  const lines = stdout.length === 0 ? [] : stdout.slice(0, -1).split("\n");
  return lines.map((line, position) => {
    const groups = LITERAL_LINE.exec(line)?.groups;
    if (groups === undefined || Number(groups.index) !== position)
      throw new R2UnityOutputDrift(
        `r2unity -z line ${String(position + 1)} is not an indexed literal.`,
      );
    const fileOffset = Number.parseInt(groups.offset ?? "", 16);
    const length = Number(groups.bytes);
    if (groups.invalid !== undefined || fileOffset + length > metadata.length)
      throw new R2UnityOutputDrift(
        `String literal ${String(position)} lies outside global-metadata.dat; the file may be truncated, encrypted or a different wire layout.`,
      );
    const bytes = metadata.subarray(fileOffset, fileOffset + length);
    if (!unescapeR2UnityLiteral(groups.text ?? "").equals(bytes))
      throw new R2UnityOutputDrift(
        `r2unity's rendering of string literal ${String(position)} disagrees with the metadata bytes at 0x${fileOffset.toString(16)}.`,
      );
    let text: string;
    let valid = true;
    try {
      text = UTF8.decode(bytes);
    } catch {
      text = LOSSY_UTF8.decode(bytes);
      valid = false;
    }
    return {
      index: position,
      file_offset: fileOffset,
      bytes: length,
      text,
      utf8_valid: valid,
      hex: valid ? null : bytes.toString("hex"),
    };
  });
};

/** Normalize `-P -j` and `-R -j` into one list, P/Invoke first. */
export const parseR2UnityInterop = (
  pinvokesStdout: string,
  reverseStdout: string,
): { readonly wireVersion: number; readonly entries: Il2CppInterop[] } => {
  const forward = parseJson(pinvokesOutputSchema, "-P -j", pinvokesStdout);
  const reverse = parseJson(
    reversePinvokesOutputSchema,
    "-R -j",
    reverseStdout,
  );
  if (forward.version !== reverse.version)
    throw new R2UnityOutputDrift(
      "r2unity -P and -R reported different metadata wire versions.",
    );
  return {
    wireVersion: forward.version,
    entries: [
      ...forward.pinvokes.map((item): Il2CppInterop => ({
        kind: "pinvoke",
        image: item.image,
        method: item.method,
        token: item.token,
        flags: item.flags,
        iflags: item.iflags,
        attribute: null,
        dll: item.dll,
        entry: item.entry,
        wrapper_address: null,
        wrapper_index: null,
        confidence: item.confidence,
      })),
      ...reverse.reverse_pinvokes.map((item): Il2CppInterop => ({
        kind: "reverse_pinvoke",
        image: item.image,
        method: item.method,
        token: item.token,
        flags: item.flags,
        iflags: item.iflags,
        attribute: item.attribute === "reverse" ? null : item.attribute,
        dll: null,
        entry: null,
        wrapper_address: item.wrapper_va ?? null,
        wrapper_index: item.wrapper_index ?? null,
        confidence: item.confidence,
      })),
    ],
  };
};

const propertyValue = (
  properties: readonly { readonly name: string; readonly value: string }[],
  name: string,
): string => {
  const matches = properties.filter((item) => item.name === name);
  const [match] = matches;
  if (matches.length !== 1 || match === undefined)
    throw new R2UnityOutputDrift(
      `r2unity -S -j component lacks exactly one ${name} property.`,
    );
  return match.value;
};

/** Normalize `-S -j` components and their reference edges. */
export const parseR2UnityAssemblies = (
  stdout: string,
): { readonly wireVersion: number; readonly entries: Il2CppAssembly[] } => {
  const sbom = parseJson(sbomOutputSchema, "-S -j", stdout);
  const wire = Number(
    propertyValue(
      sbom.metadata.component.properties,
      "unity.metadata.wire_version",
    ),
  );
  const byRef = new Map<string, { name: string; version: string }[]>();
  for (const component of sbom.components)
    byRef.set(component["bom-ref"], [
      ...(byRef.get(component["bom-ref"]) ?? []),
      { name: component.name, version: component.version },
    ]);
  const references = new Map<string, { name: string; version: string }[]>();
  for (const dependency of sbom.dependencies)
    references.set(
      dependency.ref,
      dependency.dependsOn.map((ref) => {
        const [target, ...others] = byRef.get(ref) ?? [];
        if (target === undefined || others.length > 0)
          throw new R2UnityOutputDrift(
            `r2unity -S -j dependency ${ref} does not name exactly one component.`,
          );
        return target;
      }),
    );
  const entries = sbom.components.map((component): Il2CppAssembly => {
    const read = (name: string) => propertyValue(component.properties, name);
    const token = read("dotnet.public_key_token");
    const imageIndex = Number(read("il2cpp.image_index"));
    if (
      !Number.isSafeInteger(imageIndex) ||
      !/^(?:[0-9a-f]{16})?$/u.test(token)
    )
      throw new R2UnityOutputDrift(
        `r2unity -S -j component ${component.name} has malformed identity properties.`,
      );
    return {
      name: component.name,
      version: component.version,
      culture: read("dotnet.culture"),
      public_key_token: token === "" ? null : token,
      image: read("il2cpp.image"),
      image_index: imageIndex,
      token: read("il2cpp.token"),
      flags: read("dotnet.flags"),
      hash_algorithm: read("dotnet.hash_alg"),
      references:
        (byRef.get(component["bom-ref"])?.length ?? 0) === 1
          ? (references.get(component["bom-ref"]) ?? [])
          : [],
    };
  });
  if (!Number.isSafeInteger(wire) || wire <= 0)
    throw new R2UnityOutputDrift(
      "r2unity -S -j did not report a metadata wire version.",
    );
  return { wireVersion: wire, entries };
};
