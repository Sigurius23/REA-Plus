/**
 * A Godot 3 script, run with godot3 -s, that builds binary resources,
 * scenes and save files with the engine itself, reads each back, and writes
 * what Godot sees to out/reference.json: every stored property in var2str
 * notation (and whether it equals the class default), scene nodes and
 * connections from SceneState, and the values written to each save.
 */
export const GODOT3_GENERATOR = String.raw`extends SceneTree

# Builds resources, scenes and save files with Godot 3 itself, then reads each
# binary file back and writes what Godot sees as JSON for comparison.

var out = "res://out"
var report = {}

func text(v):
	match typeof(v):
		TYPE_NIL:
			return "null"
		TYPE_STRING:
			return to_json(v)
		TYPE_OBJECT:
			if v == null:
				return "null"
			if v is Resource:
				var p = v.resource_path
				if p.find("::") >= 0:
					return "SubResource(%s)" % to_json(p.split("::")[1])
				if p == "":
					return "SubResource(?)"
				return "ExtResource(%s)" % to_json(p)
			return "Object"
		TYPE_ARRAY:
			var parts = []
			for x in v:
				parts.append(text(x))
			return "[" + PoolStringArray(parts).join(", ") + "]"
		TYPE_DICTIONARY:
			var parts = []
			for k in v:
				parts.append(text(k) + ": " + text(v[k]))
			return "{" + PoolStringArray(parts).join(", ") + "}"
		TYPE_STRING_ARRAY:
			var parts = []
			for x in v:
				parts.append(to_json(x))
			return "PoolStringArray(" + PoolStringArray(parts).join(", ") + ")"
	return var2str(v)

func stored(o):
	var fresh = ClassDB.instance(o.get_class()) if ClassDB.can_instance(o.get_class()) else null
	var known = {}
	if fresh != null:
		for p in fresh.get_property_list():
			known[p.name] = true
	var props = {}
	for p in o.get_property_list():
		if p.usage & PROPERTY_USAGE_STORAGE == 0:
			continue
		var value = o.get(p.name)
		var default = fresh.get(p.name) if known.has(p.name) else null
		props[p.name] = {"value": text(value), "default": known.has(p.name) and typeof(default) == typeof(value) and default == value}
	if fresh != null and not (fresh is Reference):
		fresh.free()
	return props

func collect(res, found):
	for p in res.get_property_list():
		if p.usage & PROPERTY_USAGE_STORAGE == 0:
			continue
		walk(res.get(p.name), found)

func walk(v, found):
	if typeof(v) == TYPE_OBJECT and v != null and v is Resource and v.resource_path.find("::") >= 0:
		var id = v.resource_path.split("::")[1]
		if not found.has(id):
			found[id] = v
			collect(v, found)
	elif typeof(v) == TYPE_ARRAY:
		for x in v:
			walk(x, found)
	elif typeof(v) == TYPE_DICTIONARY:
		for k in v:
			walk(k, found)
			walk(v[k], found)

func describe(path):
	var res = ResourceLoader.load(path, "", true)
	var entry = {"type": res.get_class(), "resources": {"main": stored(res)}}
	var found = {}
	collect(res, found)
	if res is PackedScene:
		var state = res.get_state()
		var nodes = []
		for i in state.get_node_count():
			var props = {}
			for j in state.get_node_property_count(i):
				var value = state.get_node_property_value(i, j)
				walk(value, found)
				props[state.get_node_property_name(i, j)] = text(value)
			var instance = state.get_node_instance(i)
			nodes.append({
				"path": str(state.get_node_path(i)),
				"type": state.get_node_type(i),
				"instance": text(instance) if instance != null else null,
				"groups": Array(state.get_node_groups(i)),
				"properties": props,
			})
		var connections = []
		for i in state.get_connection_count():
			var binds = []
			for b in state.get_connection_binds(i):
				binds.append(text(b))
			connections.append({
				"from": str(state.get_connection_source(i)),
				"signal": state.get_connection_signal(i),
				"to": str(state.get_connection_target(i)),
				"method": state.get_connection_method(i),
				"flags": state.get_connection_flags(i),
				"binds": binds,
			})
		entry["nodes"] = nodes
		entry["connections"] = connections
	for id in found:
		entry["resources"][id] = stored(found[id])
	return entry

func save_both(name, res):
	for compressed in [false, true]:
		var path = "%s/%s%s.%s" % [out, name, "_z" if compressed else "", "scn" if res is PackedScene else "res"]
		var err = ResourceSaver.save(path, res, ResourceSaver.FLAG_COMPRESS if compressed else 0)
		if err != OK:
			printerr("save failed ", path, " ", err)
			continue
		report[path.replace("res://out/", "")] = describe(path)

func resources():
	var gradient = Gradient.new()
	gradient.add_point(0.3, Color(0.1, 0.2, 0.3, 0.4))
	gradient.add_point(0.75, Color.crimson)
	save_both("gradient", gradient)
	var curve = Curve2D.new()
	for i in 6:
		curve.add_point(Vector2(i * 13.5, -i * 2.25), Vector2(1, 0.5), Vector2(-1, 0.25))
	save_both("curve", curve)
	var style = StyleBoxFlat.new()
	style.bg_color = Color("#ff336699")
	style.border_width_left = 7
	style.corner_radius_top_left = 12
	style.shadow_offset = Vector2(3, -4)
	style.anti_aliasing = false
	save_both("style", style)
	var anim = Animation.new()
	anim.length = 2.5
	anim.loop = true
	var t = anim.add_track(Animation.TYPE_VALUE)
	anim.track_set_path(t, NodePath("Sprite:position"))
	anim.track_insert_key(t, 0.0, Vector2(0, 0))
	anim.track_insert_key(t, 1.25, Vector2(64, -32.5))
	var t2 = anim.add_track(Animation.TYPE_TRANSFORM)
	anim.track_set_path(t2, NodePath("Arm/Bone"))
	anim.transform_track_insert_key(t2, 0.5, Vector3(1, 2, 3), Quat(0, 0.7071068, 0, 0.7071068), Vector3(1, 1, 2))
	var t3 = anim.add_track(Animation.TYPE_METHOD)
	anim.track_set_path(t3, NodePath("."))
	anim.track_insert_key(t3, 2.0, {"method": "explode", "args": [3, "big", null]})
	save_both("animation", anim)
	var mesh = ArrayMesh.new()
	var arrays = []
	arrays.resize(Mesh.ARRAY_MAX)
	arrays[Mesh.ARRAY_VERTEX] = PoolVector3Array([Vector3(0, 0, 0), Vector3(1, 0, 0), Vector3(0, 1, 0.5)])
	arrays[Mesh.ARRAY_COLOR] = PoolColorArray([Color.red, Color.green, Color(0, 0, 1, 0.5)])
	arrays[Mesh.ARRAY_INDEX] = PoolIntArray([0, 1, 2])
	mesh.add_surface_from_arrays(Mesh.PRIMITIVE_TRIANGLES, arrays)
	save_both("mesh", mesh)
	var material = SpatialMaterial.new()
	material.albedo_color = Color(0.5, 0.25, 0.125, 1)
	material.uv1_scale = Vector3(2, 3, 4)
	material.metallic = 0.8
	save_both("material", material)
	var key = InputEventKey.new()
	key.scancode = KEY_SPACE
	key.shift = true
	save_both("input", key)
	var translation = Translation.new()
	translation.locale = "de"
	translation.add_message("Hello", "Hallo")
	translation.add_message("Bye", "Tschüss \"ok\"\n")
	save_both("translation", translation)
	var image = Image.new()
	image.create(4, 3, false, Image.FORMAT_RGBA8)
	image.fill(Color(0.2, 0.4, 0.6, 1))
	image.set_pixel(1, 1, Color.white)
	var texture = ImageTexture.new()
	texture.create_from_image(image, 0)
	save_both("texture", texture)
	var env = Environment.new()
	env.background_mode = Environment.BG_COLOR
	env.background_color = Color(0.1, 0.1, 0.15)
	env.fog_enabled = true
	env.adjustment_brightness = 1.25
	save_both("environment", env)
	var theme = Theme.new()
	theme.set_color("font_color", "Label", Color.gold)
	theme.set_constant("margin", "Panel", -3)
	theme.set_stylebox("panel", "Panel", style)
	save_both("theme", theme)
	var bitmap = BitMap.new()
	bitmap.create(Vector2(11, 3))
	bitmap.set_bit(Vector2(2, 1), true)
	save_both("bitmap", bitmap)
	var shape = ConvexPolygonShape2D.new()
	shape.points = PoolVector2Array([Vector2(0, 0), Vector2(10, 0), Vector2(5, 8.5)])
	save_both("shape", shape)

func scenes():
	var child_root = Node2D.new()
	child_root.name = "Enemy"
	var child_sprite = Sprite.new()
	child_sprite.name = "Body"
	child_root.add_child(child_sprite)
	child_sprite.owner = child_root
	var child_scene = PackedScene.new()
	child_scene.pack(child_root)
	ResourceSaver.save(out + "/enemy.scn", child_scene)
	var enemy = load(out + "/enemy.scn")

	var root = Node2D.new()
	root.name = "Level"
	root.set_meta("difficulty", {"name": "hard", "waves": [1, 2, 3]})
	var sprite = Sprite.new()
	sprite.name = "Player"
	sprite.position = Vector2(12.5, -40)
	sprite.modulate = Color(1, 0.5, 0.25, 0.75)
	sprite.add_to_group("players", true)
	sprite.add_to_group("persist", true)
	root.add_child(sprite)
	var label = Label.new()
	label.name = "Hud Label"
	label.text = "Score: 0 — ünïcødé"
	sprite.add_child(label)
	var timer = Timer.new()
	timer.name = "Timer"
	timer.wait_time = 0.75
	timer.one_shot = true
	root.add_child(timer)
	sprite.region_enabled = true
	sprite.region_rect = Rect2(4, 8, 15.5, 16)
	var spatial = Spatial.new()
	spatial.name = "Gizmo3D"
	spatial.transform = Transform(Basis(Vector3(0, 1, 0), 0.5), Vector3(1, -2, 3.25))
	root.add_child(spatial)
	var body = StaticBody2D.new()
	body.name = "Wall"
	root.add_child(body)
	var collision = CollisionShape2D.new()
	collision.name = "Shape"
	var rect = RectangleShape2D.new()
	rect.extents = Vector2(32, 8)
	collision.shape = rect
	body.add_child(collision)
	var player = AnimationPlayer.new()
	player.name = "Anims"
	var anim = Animation.new()
	anim.length = 1.5
	player.add_animation("idle", anim)
	root.add_child(player)
	for i in 2:
		var e = enemy.instance()
		e.name = "Enemy%d" % i
		e.position = Vector2(100 * i, 7)
		root.add_child(e)
	for n in [sprite, label, timer, spatial, body, collision, player, root.get_node("Enemy0"), root.get_node("Enemy1")]:
		n.owner = root
	timer.connect("timeout", sprite, "hide", [], CONNECT_PERSIST)
	sprite.connect("visibility_changed", timer, "start", [2.5, "fast", Vector2(1, 2)], CONNECT_PERSIST | CONNECT_DEFERRED | CONNECT_ONESHOT)
	var scene = PackedScene.new()
	scene.pack(root)
	save_both("level", scene)

func containers():
	var values = [
		{"player": "Ana", "hp": 87, "gold": 12345678901, "ratio": 0.1, "alive": true, "pet": null,
		 "pos": Vector2(1.5, -2), "where": Vector3(1, 2, 3), "tint": Color(0.1, 0.2, 0.3, 0.4),
		 "items": [{"name": "sword", "count": 1}, {"name": "potion", "count": 12}],
		 "flags": PoolByteArray([1, 2, 255]), "scores": PoolIntArray([10, -20, 30]),
		 "weights": PoolRealArray([0.5, 1.25]), "names": PoolStringArray(["a", "ß", "\"q\""]),
		 "path": NodePath("World/Player:position"), 7: "int key", "xform": Transform2D(0.5, Vector2(3, 4))},
		"second value",
		PoolVector2Array([Vector2(1, 2), Vector2(3, 4)]),
	]
	var big = ""
	for i in 3000:
		big += "row %d of the repeated save line; " % (i % 37)
	values.append(big)
	var names = ["fastlz", "deflate", "zstd", "gzip"]
	var reference = []
	for v in values:
		reference.append(text(v))
	for mode in 4:
		var f = File.new()
		f.open_compressed(out + "/save_%s.dat" % names[mode], File.WRITE, mode)
		for v in values:
			f.store_var(v)
		f.close()
		report["save_%s.dat" % names[mode]] = {"values": reference}
	var plain = File.new()
	plain.open(out + "/save_plain.dat", File.WRITE)
	for v in values:
		plain.store_var(v)
	plain.close()
	report["save_plain.dat"] = {"values": reference}
	var secret = File.new()
	secret.open_encrypted_with_pass(out + "/save_password.dat", File.WRITE, "hunter2")
	for v in values:
		secret.store_var(v)
	secret.close()
	report["save_password.dat"] = {"values": reference, "password": "hunter2"}
	var key = PoolByteArray()
	for i in 32:
		key.append((i * 7 + 3) % 256)
	var keyed = File.new()
	keyed.open_encrypted(out + "/save_key.dat", File.WRITE, key)
	for v in values:
		keyed.store_var(v)
	keyed.close()
	report["save_key.dat"] = {"values": reference, "key": key.hex_encode()}

func _init():
	Directory.new().make_dir_recursive(out)
	resources()
	scenes()
	containers()
	var f = File.new()
	f.open(out + "/reference.json", File.WRITE)
	f.store_string(to_json(report))
	f.close()
	quit()
`;
