import com.atxx.jhmcp.*;
import com.google.gson.*;
import com.google.gson.GsonBuilder;
import io.modelcontextprotocol.kotlin.sdk.server.*;
import io.modelcontextprotocol.kotlin.sdk.types.*;
import jadx.api.*;
import jadx.api.plugins.input.data.IFieldRef;
import jadx.api.plugins.input.data.IMethodRef;
import jadx.api.plugins.input.data.annotations.EncodedType;
import jadx.api.plugins.input.data.annotations.EncodedValue;
import jadx.api.plugins.input.data.annotations.IAnnotation;
import jadx.api.plugins.input.data.attributes.JadxAttrType;
import jadx.api.plugins.input.data.attributes.types.AnnotationsAttr;
import jadx.core.dex.nodes.*;
import java.io.PrintStream;
import java.util.*;
import java.util.concurrent.CountDownLatch;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import kotlin.Unit;
import kotlin.coroutines.EmptyCoroutineContext;
import kotlinx.coroutines.BuildersKt;
import kotlinx.io.CoreKt;
import kotlinx.io.JvmCoreKt;
import kotlinx.serialization.json.JsonObject;

/** REA+-owned metadata boundary for the unmodified jadx-headless-mcp 0.7.1 JAR. */
class ReaJadxBridge {
  /** Gson omits null map values by default; the protocol requires explicit nulls. */
  private static final Gson JSON = new GsonBuilder().serializeNulls().create();

  /**
   * Annotation and constant-value scopes mirror the dex sections the input
   * readers parse; none of them load or execute code.
   */
  private static final int ANNOTATION_LIMIT = 64;
  private static final int INIT_FIELD_LIMIT = 256;
  private static final int ARRAY_VALUE_LIMIT = 64;
  private static final int VALUE_DEPTH_LIMIT = 8;
  private static final long SAFE_NUMBER_LIMIT = 9_007_199_254_740_991L;
  /** String-constant scan sanctions bodies through the get_method_body path. */
  private static final int SCAN_CLASS_DEFAULT = 256;
  /**
   * The scan universe is whole dex class identities; 8192 admits every class
   * of a small consumer APK in one honest, explicitly requested scan.
   */
  private static final int SCAN_CLASS_LIMIT = 8_192;
  private static final int SCAN_RESULT_DEFAULT = 200;
  private static final int SCAN_RESULT_LIMIT = 1_000;
  /**
   * Bounds the decompile cost of one pathological class; 4096 methods admits
   * every real class of a small consumer APK while still capping the worst case.
   */
  private static final int SCAN_METHOD_LIMIT = 4_096;
  private static final Pattern SMALI_STRING =
      Pattern.compile("const-string(?:/jumbo)?\\s+v\\d+,\\s*\"((?:[^\"\\\\]|\\\\.)*)\"");
  private static final Pattern JAVA_STRING =
      Pattern.compile("\"((?:[^\"\\r\\n\\\\]|\\\\.)*)\"");
  private final SessionHolder holder;
  private JadxSession indexedSession;
  private Map<String, List<ClassSnapshot>> classes = Map.of();

  private record MethodSnapshot(String name, String shortId, Map<String, Object> summary) {}
  private record ClassSnapshot(JavaClass node, List<MethodSnapshot> methods, Map<String, Object> summary,
      List<Object> classAnnotations, List<Object> staticInits, boolean valuesTruncated) {}

  private static final class InputFailure extends IllegalArgumentException {
    final String field;
    InputFailure(String field, String message) { super(message); this.field = field; }
  }

  private ReaJadxBridge(SessionHolder holder) { this.holder = holder; }

  private static CallToolResult text(String value, boolean failed) {
    return new CallToolResult(List.of(new TextContent(value, null, null)), failed, null, null);
  }

  private static CallToolResult json(Object value) { return text(JSON.toJson(value), false); }

  private static String string(JsonObject args, String name) {
    JsonElement value = JsonParser.parseString(args.toString()).getAsJsonObject().get(name);
    if (value == null || !value.isJsonPrimitive() || !value.getAsJsonPrimitive().isString())
      throw new IllegalArgumentException(name + " must be a string");
    return value.getAsString();
  }

  private static String optionalString(JsonObject args, String name) {
    JsonElement value = JsonParser.parseString(args.toString()).getAsJsonObject().get(name);
    if (value == null) return null;
    if (!value.isJsonPrimitive() || !value.getAsJsonPrimitive().isString())
      throw new IllegalArgumentException(name + " must be a string, when present");
    return value.getAsString();
  }

  private static int integer(JsonObject args, String name, int fallback) {
    JsonElement value = JsonParser.parseString(args.toString()).getAsJsonObject().get(name);
    if (value == null) return fallback;
    if (!value.isJsonPrimitive() || !value.getAsJsonPrimitive().isNumber())
      throw new IllegalArgumentException(name + " must be a nonnegative integer");
    try {
      int result = value.getAsBigDecimal().intValueExact();
      if (result < 0) throw new ArithmeticException();
      return result;
    } catch (ArithmeticException error) {
      throw new IllegalArgumentException(name + " must be a nonnegative integer", error);
    }
  }

  private JadxSession session() {
    JadxSession current = holder.current();
    if (current == null) throw new IllegalArgumentException("No APK loaded");
    return current;
  }

  private Map<String, List<ClassSnapshot>> index() {
    JadxSession current = session();
    if (indexedSession != current) {
      Map<String, List<ClassSnapshot>> built = new LinkedHashMap<>();
      if (!current.getClasses().isEmpty()) {
        JadxDecompiler decompiler = current.getClasses().get(0).getClassNode().root().getDecompiler();
        // JavaClass.getMethods/getFields/getInnerClasses all load code. Raw nodes do not.
        // Snapshot every identity before code generation can rewrite aliases or members.
        // Constant initial values and class annotations live on raw nodes too, but
        // forced code generation clears them, so they are captured here as well.
        for (JavaClass cls : decompiler.getClassesWithInners()) {
          ClassNode node = cls.getClassNode();
          List<MethodNode> ordered = new ArrayList<>(node.getMethods());
          ordered.sort(Comparator.comparing(MethodNode::getAlias));
          List<MethodSnapshot> methods = ordered.stream().map(method -> {
            String name = method.getAlias();
            String signature = name + "(" + method.getArgTypes().stream()
                .map(Object::toString).collect(Collectors.joining(", "))
                + "): " + method.getReturnType().toString();
            return new MethodSnapshot(name, method.getMethodInfo().getShortId(), Map.of(
                "name", name, "signature", signature,
                "is_constructor", method.isConstructor(), "def_pos", 0));
          }).toList();
          List<Map<String, Object>> fields = node.getFields().stream()
              .sorted(Comparator.comparing(FieldNode::getAlias))
              .map(field -> Map.<String, Object>of("name", field.getAlias(),
                  "type", field.getType().toString(), "def_pos", 0)).toList();
          List<String> inner = node.getInnerClasses().stream().map(ClassNode::getFullName).toList();
          Map<String, Object> summary = Map.of(
              "full_name", cls.getFullName(), "name", cls.getName(),
              "method_count", methods.size(), "field_count", fields.size(),
              "inner_class_count", inner.size(), "inner_classes", inner,
              "methods", methods.stream().map(MethodSnapshot::summary).toList(), "fields", fields);
          Truncation valueTruncation = new Truncation();
          ValueEncoder valueEncoder = new ValueEncoder(valueTruncation);
          List<Object> annotations = encodedAnnotations(
              valueEncoder.annotations(node.get(JadxAttrType.ANNOTATION_LIST)), valueEncoder);
          List<FieldNode> constantFields = node.getFields().stream()
              .filter(field -> field.get(JadxAttrType.CONSTANT_VALUE) != null)
              .sorted(Comparator.comparing(FieldNode::getAlias)).toList();
          if (constantFields.size() > INIT_FIELD_LIMIT) valueTruncation.hit = true;
          List<Object> staticInits = new ArrayList<>();
          for (FieldNode field : constantFields.stream().limit(INIT_FIELD_LIMIT).toList())
            staticInits.add(object("name", field.getAlias(),
                "reported_type", field.getType().toString(),
                "constant", valueEncoder.value(field.get(JadxAttrType.CONSTANT_VALUE), 0)));
          built.computeIfAbsent(cls.getFullName(), ignored -> new ArrayList<>())
              .add(new ClassSnapshot(cls, methods, summary, annotations, staticInits,
                  valueTruncation.hit));
        }
      }
      classes = Collections.unmodifiableMap(built);
      indexedSession = current;
    }
    return classes;
  }

  private ClassSnapshot selected(JsonObject args) {
    Map<String, List<ClassSnapshot>> index = index();
    String name = string(args, "class_name");
    List<ClassSnapshot> candidates = index.get(name);
    if (candidates == null) throw new InputFailure("class_name", "Exact class not found: " + name
        + "; use search_android_classes to discover fully qualified names.");
    if (candidates.size() != 1) throw new InputFailure("class_name", "Ambiguous metadata class identity: " + name
        + "; raw identities: " + candidates.stream().map(candidate -> candidate.node().getRawName()).toList());
    return candidates.get(0);
  }

  private List<MethodSnapshot> methods(ClassSnapshot cls, JsonObject args) {
    String name = string(args, "method_name");
    List<MethodSnapshot> result = cls.methods().stream().filter(method -> method.name().equals(name)).toList();
    if (result.isEmpty()) throw new InputFailure("method_name", "Method not found: " + name
        + "; use inspect_android_class to discover available methods.");
    return result;
  }

  private JavaMethod method(ClassSnapshot cls, MethodSnapshot selected) {
    JavaMethod result = cls.node().searchMethodByShortId(selected.shortId());
    if (result == null) throw new IllegalArgumentException("Method identity no longer available: " + selected.shortId());
    return result;
  }

  private static String unescape(String raw) {
    StringBuilder out = new StringBuilder(raw.length());
    for (int index = 0; index < raw.length(); index++) {
      char character = raw.charAt(index);
      if (character != '\\' || index + 1 >= raw.length()) {
        out.append(character);
        continue;
      }
      char next = raw.charAt(++index);
      switch (next) {
        case 'n': out.append('\n'); break;
        case 'r': out.append('\r'); break;
        case 't': out.append('\t'); break;
        case 'b': out.append('\b'); break;
        case 'f': out.append('\f'); break;
        case 'u': {
          if (index + 4 < raw.length()) {
            try {
              out.append((char) Integer.parseInt(raw.substring(index + 1, index + 5), 16));
              index += 4;
            } catch (RuntimeException ignored) {
              out.append('u');
            }
          } else out.append('u');
          break;
        }
        default: out.append(next); break;
      }
    }
    return out.toString();
  }

  /** Count same-name overloads the way the TS projector orders them. */
  private static int overloadCountOf(ClassSnapshot cls, String name) {
    int count = 0;
    for (MethodSnapshot snapshot : cls.methods())
      if (snapshot.name().equals(name)) count++;
    return count;
  }

  private void harvestStringConstants(
      List<Map<String, Object>> items,
      ClassSnapshot cls,
      MethodSnapshot snapshot,
      int overloadIndex,
      String body,
      String kind,
      boolean fellBack,
      String query) {
    String representation = kind.equals("smali") ? "smali" : "java";
    Matcher matches = representation.equals("smali")
        ? SMALI_STRING.matcher(body) : JAVA_STRING.matcher(body);
    while (matches.find()) {
      String value = unescape(matches.group(1));
      if (value.contains(query)) items.add(object(
          "class_name", cls.node().getFullName(),
          "method_name", snapshot.name(),
          "overload_index", overloadIndex,
          "overload_count", overloadCountOf(cls, snapshot.name()),
          "value", value,
          "representation", representation,
          "fell_back", fellBack));
    }
  }

  /**
   * Case-sensitive substring scan over harvested string constants. Method
   * bodies come from the same decompile-or-smali path as get_method_body, so a
   * body that cannot be produced is skipped and reported, not denied.
   */
  private Map<String, Object> searchStringConstants(JsonObject args) {
    Map<String, List<ClassSnapshot>> index = index();
    String query = string(args, "query");
    int classLimit = Math.min(integer(args, "class_limit", SCAN_CLASS_DEFAULT), SCAN_CLASS_LIMIT);
    int resultLimit = Math.min(integer(args, "results_limit", SCAN_RESULT_DEFAULT), SCAN_RESULT_LIMIT);
    JadxSession current = session();
    int totalClasses = 0;
    for (List<ClassSnapshot> group : index.values()) totalClasses += group.size();
    List<Map<String, Object>> items = new ArrayList<>();
    int scannedClasses = 0;
    int scannedMethods = 0;
    int skippedMethods = 0;
    boolean truncated = false;
    scan: for (List<ClassSnapshot> group : index.values()) {
      for (ClassSnapshot cls : group) {
        if (scannedClasses >= classLimit || items.size() >= resultLimit) {
          truncated = true;
          break scan;
        }
        scannedClasses++;
        Map<String, Integer> overloadsSeen = new HashMap<>();
        int methodsScanned = 0;
        for (MethodSnapshot snapshot : cls.methods()) {
          if (items.size() >= resultLimit) {
            truncated = true;
            break scan;
          }
          if (methodsScanned >= SCAN_METHOD_LIMIT) {
            truncated = true;
            break;
          }
          methodsScanned++;
          scannedMethods++;
          int overloadsOfName = overloadsSeen.merge(snapshot.name(), 1, Integer::sum) - 1;
          try {
            JadxSession.SmartCode code = current.getMethodBodySmart(
                method(cls, snapshot), current.getMaxSourceBytes(), true);
            harvestStringConstants(items, cls, snapshot, overloadsOfName,
                code.getText(), code.getKind(), code.getFellBack(), query);
          } catch (Throwable failure) {
            // Decompile, smali and source-generation failures skip one method;
            // the scan itself stays alive and reports the skip count.
            skippedMethods++;
          }
        }
      }
    }
    Map<String, Object> result = new LinkedHashMap<>();
    result.put("query", query);
    result.put("total_classes", totalClasses);
    result.put("scanned_classes", scannedClasses);
    result.put("scanned_methods", scannedMethods);
    result.put("skipped_methods", skippedMethods);
    result.put("truncated", truncated);
    result.put("coverage", truncated ? "partial" : "complete");
    result.put("items", items);
    return result;
  }

  private static final class Truncation {
    boolean hit;
  }

  /**
   * Project parsed dex annotations and encoded values into portable JSON.
   * Enumerated field and method references keep only identity strings; no
   * class loading ever resolves them.
   */
  private static final class ValueEncoder {
    private static final String KIND = "kind";
    private static final String VALUE = "value";
    private final Truncation truncation;

    private ValueEncoder(Truncation truncation) { this.truncation = truncation; }

    private static String lower(EncodedType type) {
      String name = type.name();
      return name.substring("ENCODED_".length()).toLowerCase(Locale.ROOT);
    }

    private void overLimit() { truncation.hit = true; }

    private List<IAnnotation> annotations(AnnotationsAttr attr) {
      if (attr == null) return List.of();
      List<String> keys = attr.getAll().stream()
          .map(IAnnotation::getAnnotationClass).distinct().sorted().toList();
      List<IAnnotation> selected = new ArrayList<>();
      for (String key : keys) {
        IAnnotation ann = attr.get(key);
        if (ann == null) continue;
        if (selected.size() >= ANNOTATION_LIMIT) { overLimit(); break; }
        selected.add(ann);
      }
      return selected;
    }

    private Map<String, Object> annotation(IAnnotation ann, int depth) {
      Map<String, Object> values = new LinkedHashMap<>();
      for (Map.Entry<String, EncodedValue> entry
          : ((Map<String, EncodedValue>) ann.getValues()).entrySet().stream()
              .sorted(Map.Entry.comparingByKey()).collect(Collectors.toList()))
        values.put(entry.getKey(), value(entry.getValue(), depth + 1));
      return object("class", ann.getAnnotationClass(),
          "visibility", String.valueOf(ann.getVisibility()).toLowerCase(Locale.ROOT),
          "values", values);
    }

    private Map<String, Object> value(EncodedValue encoded, int depth) {
      EncodedType type = encoded.getType();
      Object raw = encoded.getValue();
      switch (type) {
        case ENCODED_NULL:
          return object(KIND, "null", VALUE, null);
        case ENCODED_LONG: {
          long longValue = ((Number) raw).longValue();
          boolean safe = Math.abs(longValue) <= SAFE_NUMBER_LIMIT;
          return object(KIND, "long",
              VALUE, safe ? (Object) Long.valueOf(longValue) : String.valueOf(longValue));
        }
        case ENCODED_BOOLEAN, ENCODED_BYTE, ENCODED_SHORT, ENCODED_INT:
          return object(KIND, lower(type), VALUE, raw);
        case ENCODED_CHAR, ENCODED_STRING, ENCODED_TYPE:
          return object(KIND, lower(type), VALUE, String.valueOf(raw));
        case ENCODED_FLOAT, ENCODED_DOUBLE: {
          double number = ((Number) raw).doubleValue();
          return object(KIND, lower(type),
              VALUE, Double.isFinite(number) ? (Object) Double.valueOf(number) : String.valueOf(raw));
        }
        case ENCODED_ENUM, ENCODED_FIELD: {
          IFieldRef ref = (IFieldRef) raw;
          return object(KIND, "field", VALUE, object(
              "class", ref.getParentClassType(), "name", ref.getName(), "type", ref.getType()));
        }
        case ENCODED_METHOD:
          IMethodRef ref = (IMethodRef) raw;
          return object(KIND, "method", VALUE, object(
              "class", ref.getParentClassType(), "name", ref.getName(),
              "params", List.copyOf(ref.getArgTypes()), "return", ref.getReturnType()));
        case ENCODED_ARRAY: {
          if (depth > VALUE_DEPTH_LIMIT) {
            overLimit();
            return object(KIND, "other", VALUE, String.valueOf(raw));
          }
          List<EncodedValue> items = (List<EncodedValue>) raw;
          if (items.size() > ARRAY_VALUE_LIMIT) overLimit();
          List<Object> values = new ArrayList<>();
          for (EncodedValue item : items.stream().limit(ARRAY_VALUE_LIMIT).toList())
            values.add(value(item, depth + 1));
          return object(KIND, "array", VALUE, values);
        }
        case ENCODED_ANNOTATION: {
          if (depth > VALUE_DEPTH_LIMIT) {
            overLimit();
            return object(KIND, "other", VALUE, String.valueOf(raw));
          }
          return object(KIND, "annotation", VALUE, annotation((IAnnotation) raw, depth));
        }
        default:
          overLimit();
          return object(KIND, "other", VALUE, String.valueOf(raw));
      }
    }
  }

  private static Map<String, Object> object(Object... fields) {
    Map<String, Object> map = new LinkedHashMap<>();
    for (int index = 0; index < fields.length; index += 2)
      map.put((String) fields[index], fields[index + 1]);
    return map;
  }

  private Map<String, Object> annotationValues(ClassSnapshot cls, JsonObject args) {
    String methodName = optionalString(args, "method_name");
    Truncation truncation = new Truncation();
    ValueEncoder encoder = new ValueEncoder(truncation);
    Map<String, Object> result = new LinkedHashMap<>();
    result.put("class_name", cls.summary().get("full_name"));
    if (methodName == null) {
      result.put("method_name", null);
      // Served from the pre-codegen snapshot; forced decomposition clears live attrs.
      result.put("annotations", cls.classAnnotations());
      result.put("static_inits", cls.staticInits());
      truncation.hit = cls.valuesTruncated();
    } else {
      List<MethodSnapshot> overloads = methods(cls, args);
      int index = integer(args, "overload_index", 0);
      if (index >= overloads.size()) throw new InputFailure("overload_index",
          "overload_index out of range: " + index);
      MethodNode node = method(cls, overloads.get(index)).getMethodNode();
      List<IAnnotation> annotations = encoder.annotations(node.get(JadxAttrType.ANNOTATION_LIST));
      result.put("method_name", methodName);
      result.put("overload_index", index);
      result.put("overload_count", overloads.size());
      result.put("annotations", encodedAnnotations(annotations, encoder));
    }
    result.put("truncated", truncation.hit);
    return result;
  }

  private List<Object> encodedAnnotations(List<IAnnotation> annotations, ValueEncoder encoder) {
    List<Object> items = new ArrayList<>();
    for (IAnnotation annotation : annotations)
      items.add(encoder.annotation(annotation, 0));
    return items;
  }

  private CallToolResult handle(String name, JsonObject args) {
    if (name.equals("rea_jvm_status")) return json(Map.of(
        "engine_reported_version", BuildInfo.VERSION,
        "max_heap_bytes", Runtime.getRuntime().maxMemory(),
        "available_processors", Runtime.getRuntime().availableProcessors(),
        "java_version", System.getProperty("java.version"),
        "metadata_scope", "parsed_members"));
    JadxSession current = session();
    if (name.equals("list_classes")) {
      List<String> names = current.getClassFqns();
      int offset = integer(args, "offset", 0);
      int limit = integer(args, "limit", 200);
      int start = Math.min(offset, names.size());
      int end = (int) Math.min((long) start + limit, names.size());
      return json(Map.of("total", names.size(), "offset", offset, "limit", limit,
          "items", names.subList(start, end)));
    }
    if (name.equals("search_string_constants")) return json(searchStringConstants(args));
    ClassSnapshot cls = selected(args);
    if (name.equals("get_annotation_values")) return json(annotationValues(cls, args));
    if (name.equals("get_class_summary")) return json(cls.summary());
    if (name.equals("get_method_body")) {
      List<MethodSnapshot> overloads = methods(cls, args);
      int index = integer(args, "overload_index", 0);
      if (index >= overloads.size()) throw new InputFailure("overload_index", "overload_index out of range: " + index);
      JavaMethod method = method(cls, overloads.get(index));
      JadxSession.SmartCode code = current.getMethodBodySmart(method, current.getMaxSourceBytes(), true);
      return json(Map.of("class_name", cls.summary().get("full_name"),
          "method_name", overloads.get(index).name(), "full_name", method.getFullName(),
          "overload_index", index, "overload_count", overloads.size(),
          "mode", code.getKind(), "fell_back", code.getFellBack(),
          "markers", code.getMarkers(), "body", code.getText()));
    }
    List<JavaNode> uses;
    String target = string(args, "class_name");
    if (name.equals("get_xrefs_to_class")) uses = cls.node().getUseIn();
    else {
      List<MethodSnapshot> overloads = methods(cls, args);
      if (overloads.size() != 1) throw new InputFailure("method_name", "Method references require a unique overload");
      target += "." + overloads.get(0).name();
      uses = method(cls, overloads.get(0)).getUseIn();
    }
    // REA+ consumes all references without materializing source line information.
    List<Map<String, Object>> items = uses.stream().map(node -> current.describeUsage(node, false)).toList();
    return json(Map.of("target", target, "total", uses.size(), "count", items.size(),
        "resolve_line", false, "items", items));
  }

  public static void main(String[] args) throws Exception {
    PrintStream protocolOut = System.out;
    System.setOut(System.err);
    SessionHolder holder = new SessionHolder(new SessionConfig(
        // Decompiles are cached across the whole-APK scan budget; the engine
        // unloads least-recent classes below this, which strips pass-derived
        // attributes (override markers, constant values) and degrades any body
        // re-rendered after a large scan.
        1048576, 0, 90000L, 1, List.of(), List.of(), SCAN_CLASS_LIMIT, ResourceMode.FULL));
    ServerCapabilities capabilities = new ServerCapabilities(
        new ServerCapabilities.Tools(null), null, null, null, null, null, null, Map.of());
    Server server = new Server(new Implementation("rea-jadx-bridge", "1", null, null, null),
        new ServerOptions(capabilities), "", ignored -> Unit.INSTANCE);
    SessionToolsKt.registerSessionTools(server, holder);
    ManifestToolsKt.registerManifestTools(server, holder);
    ClassToolsKt.registerClassTools(server, holder);
    MethodToolsKt.registerMethodTools(server, holder);
    XrefToolsKt.registerXrefTools(server, holder);
    ReaJadxBridge bridge = new ReaJadxBridge(holder);
    Set<String> consumed = Set.of("load_apk", "get_app_info", "get_android_manifest",
        "list_classes", "get_class_summary", "get_method_body",
        "get_xrefs_to_class", "get_xrefs_to_method");
    for (String name : new ArrayList<>(server.getTools().keySet()))
      if (!consumed.contains(name)) server.removeTool(name);
    Tool diagnostics = new Tool("rea_jvm_status",
        new ToolSchema(null, new JsonObject(Map.of()), List.of(), null),
        "Observed worker JVM and metadata scope", null, null, null, null, null, null);
    server.addTool(diagnostics, (connection, request, continuation) -> bridge.handle("rea_jvm_status", request.getArguments()));
    for (String name : List.of("list_classes", "get_class_summary",
        "get_method_body", "get_xrefs_to_class", "get_xrefs_to_method")) {
      Tool tool = server.getTools().get(name).getTool();
      server.removeTool(name);
      List<String> fields = switch (name) {
        case "list_classes" -> List.of("offset", "limit");
        case "get_method_body" -> List.of("class_name", "method_name", "overload_index");
        case "get_xrefs_to_method" -> List.of("class_name", "method_name");
        default -> List.of("class_name");
      };
      Map<String, kotlinx.serialization.json.JsonElement> properties = new LinkedHashMap<>();
      for (String field : fields) properties.put(field, tool.getInputSchema().getProperties().get(field));
      String description = switch (name) {
        case "list_classes" -> "Indexed pages of all top-level class names, with offset and limit.";
        case "get_class_summary" -> "Parsed member metadata for one exact class name; no source generation.";
        case "get_method_body" -> "Source for an exact class and stable same-name overload index, with smali fallback.";
        default -> "Complete static references to an exact class or unique method; source lines are unresolved.";
      };
      Tool narrowed = new Tool(name, new ToolSchema(null, new JsonObject(properties),
          tool.getInputSchema().getRequired(), null), description, null, null, null, null, null, null);
      server.addTool(narrowed, (connection, request, continuation) -> {
        try { return bridge.handle(name, request.getArguments()); }
        catch (InputFailure error) { return text(JSON.toJson(Map.of(
            "kind", "invalid-input", "field", error.field, "message", error.getMessage())), true); }
        catch (IllegalArgumentException error) { return text(error.getMessage(), true); }
      });
    }
    Map<String, kotlinx.serialization.json.JsonElement> annotationSchema = new LinkedHashMap<>();
    annotationSchema.put("class_name", kotlinx.serialization.json.JsonElementKt.JsonPrimitive("string"));
    annotationSchema.put("method_name", kotlinx.serialization.json.JsonElementKt.JsonPrimitive("string"));
    annotationSchema.put("overload_index", kotlinx.serialization.json.JsonElementKt.JsonPrimitive("integer"));
    java.util.List<String> required = List.of("class_name");
    Tool annotationTool = new Tool("get_annotation_values",
        new ToolSchema(null, new JsonObject(annotationSchema), required, null),
        "Declared dex annotations for one exact class, plus encoded static field initial values; with method_name, the annotations of one overload instead. Values are parsed without loading or executing classes.",
        null, null, null, null, null, null);
    server.addTool(annotationTool, (connection, request, continuation) -> {
      try { return bridge.handle("get_annotation_values", request.getArguments()); }
      catch (InputFailure error) { return text(JSON.toJson(Map.of(
          "kind", "invalid-input", "field", error.field, "message", error.getMessage())), true); }
      catch (IllegalArgumentException error) { return text(error.getMessage(), true); }
    });
    Map<String, kotlinx.serialization.json.JsonElement> searchSchema = new LinkedHashMap<>();
    searchSchema.put("query", kotlinx.serialization.json.JsonElementKt.JsonPrimitive("string"));
    searchSchema.put("class_limit", kotlinx.serialization.json.JsonElementKt.JsonPrimitive("integer"));
    searchSchema.put("results_limit", kotlinx.serialization.json.JsonElementKt.JsonPrimitive("integer"));
    Tool searchTool = new Tool("search_string_constants",
        new ToolSchema(null, new JsonObject(searchSchema), List.of("query"), null),
        "Case-sensitive dex string-constant search over every parsed class snapshot, harvested from each scanned method's decompiled Java or smali body. Bounded by class_limit (default 256, cap 8192), results_limit (default 200, cap 1000) and a per-class method budget; bodies that cannot be produced are skipped and counted.",
        null, null, null, null, null, null);
    server.addTool(searchTool, (connection, request, continuation) -> {
      try { return bridge.handle("search_string_constants", request.getArguments()); }
      catch (InputFailure error) { return text(JSON.toJson(Map.of(
          "kind", "invalid-input", "field", error.field, "message", error.getMessage())), true); }
      catch (IllegalArgumentException error) { return text(error.getMessage(), true); }
    });
    CountDownLatch done = new CountDownLatch(1);
    server.onClose(() -> { done.countDown(); return Unit.INSTANCE; });
    StdioServerTransport transport = new StdioServerTransport(
        CoreKt.buffered(JvmCoreKt.asSource(System.in)),
        CoreKt.buffered(JvmCoreKt.asSink(protocolOut)));
    transport.onClose(() -> { done.countDown(); return Unit.INSTANCE; });
    ServerSession connection = null;
    try {
      connection = BuildersKt.runBlocking(EmptyCoroutineContext.INSTANCE,
          (scope, continuation) -> server.createSession(transport, continuation));
      done.await();
    } finally {
      try {
        if (connection != null) {
          ServerSession connected = connection;
          // Unsubscribe the connection before the SDK joins its notification service.
          BuildersKt.runBlocking(EmptyCoroutineContext.INSTANCE,
              (scope, continuation) -> connected.close(continuation));
        }
      } finally {
        try {
          BuildersKt.runBlocking(EmptyCoroutineContext.INSTANCE,
              (scope, continuation) -> server.close(continuation));
        } finally {
          BuildersKt.runBlocking(EmptyCoroutineContext.INSTANCE,
              (scope, continuation) -> holder.unload(continuation));
        }
      }
    }
  }
}
