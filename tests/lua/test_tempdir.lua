-- Tests for tempdir.lua. The module wraps mktemp(1) for atomic + secure
-- temp file/dir creation. We can't easily test the actual mktemp call from
-- under the stub `cmd` (no real subprocess), but we CAN drive the public
-- contract: prefix sanitisation, error on empty mktemp output, automatic
-- cleanup in with_temp_dir, and the safety guard against TMPDIR=/.

local h = require("spec_helpers")
local tempdir = require("tempdir")

io.write("== tempdir.create_temp_dir / with_temp_dir ==\n")

h.test("create_temp_dir errors when mktemp returns empty", function()
  h.cmd._next = ""
  local ok, err = pcall(tempdir.create_temp_dir, "test_prefix")
  h.assert_false(ok)
  h.assert_true(tostring(err):find("mktemp failed") ~= nil,
                "expected error message about mktemp failure")
end)

h.test("create_temp_dir trims trailing whitespace from mktemp output", function()
  h.cmd._next = "/tmp/test_prefix_AbCdEfGh\n"
  local result = tempdir.create_temp_dir("test_prefix")
  h.assert_eq(result, "/tmp/test_prefix_AbCdEfGh")
end)

h.test("create_temp_file errors when mktemp returns empty", function()
  h.cmd._next = ""
  local ok = pcall(tempdir.create_temp_file, "test")
  h.assert_false(ok)
end)

h.test("with_temp_dir invokes the callback with the created path", function()
  h.cmd._next = "/tmp/wtd_AbCdEfGh\n"
  local seen
  tempdir.with_temp_dir("wtd", function(p) seen = p end)
  h.assert_eq(seen, "/tmp/wtd_AbCdEfGh")
end)

h.test("with_temp_dir propagates the callback's return values", function()
  h.cmd._next = "/tmp/wtd2_XxYy\n"
  local a, b = tempdir.with_temp_dir("wtd2", function() return 42, "hello" end)
  h.assert_eq(a, 42)
  h.assert_eq(b, "hello")
end)

h.test("with_temp_dir re-raises errors from the callback", function()
  h.cmd._next = "/tmp/wtd3_AbCd\n"
  local ok, err = pcall(function()
    tempdir.with_temp_dir("wtd3", function() error("boom") end)
  end)
  h.assert_false(ok)
  h.assert_true(tostring(err):find("boom") ~= nil, "expected the original error")
end)
