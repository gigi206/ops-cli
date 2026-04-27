local h = require("spec_helpers")
local pm = require("plugin_matcher")

io.write("== plugin_matcher.matches / extract ==\n")

h.test("matches returns true on the first matching pattern", function()
  h.assert_true(pm.matches("vscode-extensions.foo.bar",
                           "^vscode%-extensions%.",
                           "^jetbrains%-plugins%."))
end)

h.test("matches returns false when nothing matches", function()
  h.assert_false(pm.matches("nodejs", "^vscode%-extensions%.", "^jetbrains%-plugins%."))
end)

h.test("matches rejects nil and non-strings without erroring", function()
  h.assert_false(pm.matches(nil, ".+"))
  h.assert_false(pm.matches(42, ".+"))
end)

h.test("extract returns the first capture from any matching pattern", function()
  local id = pm.extract("vscode-extensions.foo.bar",
                        "vscode%-extensions%.(.+)",
                        "^vscode%+install=vscode%-extensions%.(.+)")
  h.assert_eq(id, "foo.bar")
end)

h.test("extract supports the install= prefix variant", function()
  local id = pm.extract("vscode+install=vscode-extensions.publisher.ext",
                        "vscode%-extensions%.(.+)",
                        "^vscode%+install=vscode%-extensions%.(.+)")
  h.assert_eq(id, "publisher.ext")
end)

h.test("extract returns nil when nothing matches", function()
  h.assert_eq(pm.extract("nodejs@20", "vscode%-extensions%.(.+)"), nil)
end)

h.test("extract rejects nil/non-string inputs", function()
  h.assert_eq(pm.extract(nil, "(.+)"), nil)
  h.assert_eq(pm.extract({}, "(.+)"), nil)
end)
