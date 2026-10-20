# JVM class and JAR decompilation

`inspect_jvm_artifact` / `inspect-jvm-artifact` lists the classes in an
explicitly selected local JAR or `.class` file and decompiles the classes you
name to Java with a caller-supplied [CFR](https://github.com/leibnitz27/cfr)
0.152. It is offline: bytecode is parsed by CFR and never loaded or executed.

```sh
export REA_CFR_JAR=/absolute/path/to/cfr-0.152.jar
rea inspect-jvm-artifact /absolute/mod.jar --json
rea inspect-jvm-artifact /absolute/mod.jar --classes com.example.mod.LicenseCheck --json
rea inspect-jvm-artifact /absolute/LicenseCheck.class --json
```

```json
{
  "name": "inspect_jvm_artifact",
  "arguments": {
    "path": "/absolute/mod.jar",
    "classes": ["com.example.mod.LicenseCheck", "com.example.mod.Main"]
  }
}
```

## Requirements

- `REA_CFR_JAR`: absolute path to `cfr-0.152.jar` (for example from Maven
  Central, `org.benf:cfr:0.152`). REA+ checks that the jar reports exactly
  `CFR 0.152` and records its SHA-256. REA+ does not download or install it.
- A Java runtime: `JAVA_HOME/bin/java` when `JAVA_HOME` is set, otherwise
  `java` on `PATH`. CFR 0.152 runs on Java 8 and later.

## What the result contains

- `artifact`: the selected path, SHA-256, size and kind (`class` or `jar`).
- `classes`: every class entry in entry order. For a JAR, entries under
  `META-INF/` (including multi-release copies) and `module-info`/`package-info`
  descriptors are omitted. A standalone class file lists itself with a `null`
  entry.
- `decompiled`: one source per outermost class, with the requested binary
  names it covers, the bytecode SHA-256, the class-file version (`major`,
  `minor`, `java_release`), the CFR source text and its SHA-256, and
  `cfr_reported_failures` when CFR embedded a decompilation-failure comment.
- `tool_profile`: the CFR jar path and SHA-256, the Java command and version
  banner, and the exact CFR arguments (the private copy appears as
  `<private copy>`).

A JAR is only listed until you name classes; a `.class` file is always
decompiled. Nested classes such as `Outer$Inner` return `Outer`'s source,
because CFR writes nested classes into their outermost class. Naming a class
the JAR does not contain, or selecting a file that is neither a class file nor
a ZIP/JAR, is an input error.

## Boundaries

- Decompiled Java is CFR's reconstruction, not original source. Local
  variable names, comments, generics and control-flow structure can differ.
- Classes from other JARs (dependencies, the JDK) are not resolved, so CFR may
  report missing types.
- CFR and Java are trusted caller-supplied programs. SHA-256 and version
  banners identify them, not publisher authenticity.
- Each Java process has a 300-second deadline. Decompiled sources returned
  inline are limited to 32 MiB in total; select fewer classes when a request
  exceeds it.
- The JVM's `Picked up JAVA_TOOL_OPTIONS` notices are removed from retained
  output, because they echo the ambient environment.

## Verification

`tests/boundary/providers/jvm/cfrArtifact.real.test.ts` compiles fixture
sources with `javac --release 17`, packages them with `jar` and runs the real
CFR when `REA_VERIFY_CFR_JAR` is set (otherwise a named skip). It was verified
with CFR 0.152 (jar SHA-256
`f686e8f3ded377d7bc87d216a90e9e9512df4156e75b06c655a16648ae8765b2`) on OpenJDK
21 on Linux x86-64. Android DEX/APK decompilation remains the JADX workflow in
the [Android guide](android-analysis.md).
