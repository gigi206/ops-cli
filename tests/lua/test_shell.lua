local h = require("spec_helpers")
local shell = require("shell")

io.write("== shell.shquote / shell.path_exists ==\n")

h.test("shquote wraps a plain word in single quotes", function()
  h.assert_eq(shell.shquote("foo"), "'foo'")
end)

h.test("shquote escapes embedded single quotes", function()
  -- POSIX-safe: 'a'\''b' is "a'b" outside the shell.
  h.assert_eq(shell.shquote("a'b"), "'a'\\''b'")
end)

h.test("shquote handles nil (legacy callers)", function()
  h.assert_eq(shell.shquote(nil), "''")
end)

h.test("shquote tolerates spaces and shell metachars", function()
  h.assert_eq(shell.shquote("$(rm -rf /)"), "'$(rm -rf /)'")
  h.assert_eq(shell.shquote("a b c"), "'a b c'")
end)

h.test("path_exists returns true when stub stdout matches `yes`", function()
  h.cmd._next = "yes\n"
  h.assert_true(shell.path_exists("/whatever", "f"))
end)

h.test("path_exists returns false when stub stdout is empty", function()
  h.cmd._next = ""
  h.assert_false(shell.path_exists("/whatever", "f"))
end)

h.test("path_exists returns false on non-string stub return", function()
  -- cmd.exec might raise or return non-string in degenerate cases; we
  -- care that path_exists doesn't propagate either as a true result.
  h.cmd._next = nil
  h.assert_false(shell.path_exists("/whatever", "d"))
end)

h.test("path_exists defaults to existence check when kind omitted", function()
  h.cmd._next = "yes\n"
  h.assert_true(shell.path_exists("/whatever"))
end)
