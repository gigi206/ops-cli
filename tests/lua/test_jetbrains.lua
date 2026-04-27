-- Tests for jetbrains.extract_plugin_info — the bespoke parser that splits
-- `jetbrains-plugins.<system>.<ide>.<version>.<plugin_id>` into its four
-- components. The parser handles two annoying realities:
--   * The version may carry one OR several dots (`2024.3`, `17.0.14`).
--   * The plugin_id can start with `com.`, `org.`, `jetbrains.`, etc.,
--     OR be an opaque token.
-- Because both `version` and `plugin_id` accept dots, the boundary is
-- inferred heuristically (look for a known prefix; fall back to "first
-- component that doesn't look like a year"). Misclassification here
-- silently routes plugins to the wrong directory, so coverage matters.

local h = require("spec_helpers")
local jb = require("jetbrains")

io.write("== jetbrains.is_plugin / extract_plugin_info ==\n")

h.test("is_plugin matches both jetbrains-plugins. and the install= variant", function()
  h.assert_true(jb.is_plugin("jetbrains-plugins.x86_64-linux.idea-ultimate.2024.3.com.foo"))
  h.assert_true(jb.is_plugin("jetbrains+install=jetbrains-plugins.x86_64-linux.idea-ultimate.2024.3.com.foo"))
end)

h.test("is_plugin returns false for unrelated names", function()
  h.assert_false(jb.is_plugin("nodejs"))
  h.assert_false(jb.is_plugin("vscode-extensions.foo.bar"))
  h.assert_false(jb.is_plugin(nil))
end)

h.test("extract_plugin_info parses standard com.* plugin id", function()
  local p = jb.extract_plugin_info(
    "jetbrains-plugins.x86_64-linux.idea-ultimate.2024.3.com.intellij.plugins.watcher")
  h.assert_eq(p.system, "x86_64-linux")
  h.assert_eq(p.ide, "idea-ultimate")
  h.assert_eq(p.version, "2024.3")
  h.assert_eq(p.plugin_id, "com.intellij.plugins.watcher")
end)

h.test("extract_plugin_info parses install= variant", function()
  local p = jb.extract_plugin_info(
    "jetbrains+install=jetbrains-plugins.aarch64-darwin.pycharm-professional.2024.3.org.example.plugin")
  h.assert_eq(p.system, "aarch64-darwin")
  h.assert_eq(p.ide, "pycharm-professional")
  h.assert_eq(p.version, "2024.3")
  h.assert_eq(p.plugin_id, "org.example.plugin")
end)

h.test("extract_plugin_info handles 3-part semver-style versions", function()
  local p = jb.extract_plugin_info(
    "jetbrains-plugins.x86_64-linux.webstorm.17.0.14.com.foo.bar")
  h.assert_eq(p.version, "17.0.14")
  h.assert_eq(p.plugin_id, "com.foo.bar")
end)

h.test("extract_plugin_info recognises jetbrains.* plugin ids", function()
  local p = jb.extract_plugin_info(
    "jetbrains-plugins.x86_64-linux.goland.2024.3.jetbrains.go.tool")
  h.assert_eq(p.plugin_id, "jetbrains.go.tool")
end)

h.test("extract_plugin_info returns nil for too-few segments", function()
  h.assert_eq(jb.extract_plugin_info("jetbrains-plugins.foo"), nil)
  h.assert_eq(jb.extract_plugin_info("jetbrains-plugins.x86.linux.idea"), nil)
end)

h.test("extract_plugin_info returns nil for unrelated strings", function()
  h.assert_eq(jb.extract_plugin_info("nodejs@20"), nil)
  h.assert_eq(jb.extract_plugin_info(nil), nil)
end)

h.test("get_plugins_dir maps known IDEs to JetBrains directory names (Linux)", function()
  -- Force the OS detection by setting RUNTIME (the global the module reads).
  -- h.with_mock restores _G.RUNTIME even if the assertion fails, so a
  -- regression here cannot leak the global to the next test (test_security
  -- runs right after and would observe a stale RUNTIME).
  h.with_mock(_G, "RUNTIME", { osType = "linux" }, function()
    -- We can't easily override os.getenv from Lua; just assert the suffix.
    local d = jb.get_plugins_dir("idea-ultimate", "2024.3")
    h.assert_true(d:find("/.local/share/JetBrains/IntelliJIdea2024.3/plugins$") ~= nil,
                  "expected Linux plugin path with IDE rename, got: " .. tostring(d))
  end)
end)
