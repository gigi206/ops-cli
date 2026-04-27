-- Lua test harness — runs every tests/lua/test_*.lua file in alphabetic
-- order and exits non-zero if any assertion fails.
--
-- Usage (from repo root):
--   lua tests/lua/run.lua
--
-- The harness deliberately doesn't depend on busted: the plugin only
-- exercises pure-Lua helpers in these tests, so a stock `lua5.x`
-- interpreter is enough. CI installs lua via apt (already present on
-- ubuntu-latest) and runs this file directly.

-- Anchor package.path on the spec_helpers location so the tests can be
-- launched from any working directory (`cd / && lua /path/to/run.lua`).
local here = debug.getinfo(1, "S").source:sub(2):match("^(.*)/[^/]+$") or "."
package.path = here .. "/?.lua;" .. package.path

-- Force the spec_helpers harness to be loaded fresh on each `require`
-- so its counters start at zero across test files.
local function fresh_helpers()
  package.loaded["spec_helpers"] = nil
  return require("spec_helpers")
end

local h = fresh_helpers()
local files = {
  "test_shell",
  "test_version",
  "test_flake",
  "test_plugin_matcher",
  "test_tempdir",
  "test_security",
  "test_jetbrains",
  "test_utils",
  "test_load_env",
}

for _, name in ipairs(files) do
  -- Each file uses the same helper instance so counters accumulate.
  -- We `require` rather than dofile so the harness can be re-run
  -- without re-executing the suite (idempotent in interactive use).
  local ok, err = pcall(require, name)
  if not ok then
    io.write("ERROR loading ", name, ": ", tostring(err), "\n")
    os.exit(2)
  end
end

io.write(string.format("\n%d passed, %d failed\n", h.passed, h.failed))
if h.failed > 0 then
  for _, f in ipairs(h.failures) do
    io.write("  - ", f, "\n")
  end
  os.exit(1)
end
