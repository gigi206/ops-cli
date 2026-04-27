-- Tests for security.lua::is_safe_local_path.
--
-- The function blocks unsafe local-flake paths via two layers:
--   1. Reject `..` as a path component (any position).
--   2. Reject a hard-coded list of dangerous absolute prefixes
--      (/etc/, /usr/, ~/.ssh/, ~/.aws/, …).
--   3. Resolve against cwd via `realpath -m` and require the result to be
--      a strict descendant of cwd.
--
-- The cwd-descendant check requires `pwd` and `realpath` shell calls; we
-- stub them via spec_helpers' fake_cmd. Tests that don't reach layer 3
-- assert against the cheaper layer 1+2 logic directly.

local h = require("spec_helpers")
local security = require("security")

io.write("== security.is_safe_local_path / dangerous_patterns ==\n")

h.test("rejects nil, non-string, and empty path", function()
  h.assert_false(security.is_safe_local_path(nil))
  h.assert_false(security.is_safe_local_path(""))
  h.assert_false(security.is_safe_local_path(42))
end)

h.test("rejects bare ..", function()
  h.assert_false(security.is_safe_local_path(".."))
end)

h.test("rejects ../ at the start", function()
  h.assert_false(security.is_safe_local_path("../etc/passwd"))
  h.assert_false(security.is_safe_local_path("../../etc/passwd"))
end)

h.test("rejects /../ in the middle", function()
  h.assert_false(security.is_safe_local_path("/foo/../bar"))
  h.assert_false(security.is_safe_local_path("./a/../b"))
end)

h.test("rejects /.. at the end", function()
  h.assert_false(security.is_safe_local_path("foo/.."))
end)

h.test("rejects dangerous /etc/ prefix", function()
  h.assert_false(security.is_safe_local_path("/etc/passwd"))
  h.assert_false(security.is_safe_local_path("/etc/shadow"))
end)

h.test("rejects dangerous /usr/, /bin/, /sbin/, /boot/, /root/ prefixes", function()
  h.assert_false(security.is_safe_local_path("/usr/local/bin/foo"))
  h.assert_false(security.is_safe_local_path("/bin/sh"))
  h.assert_false(security.is_safe_local_path("/sbin/init"))
  h.assert_false(security.is_safe_local_path("/boot/grub/grub.cfg"))
  h.assert_false(security.is_safe_local_path("/root/.bashrc"))
end)

h.test("rejects per-user .ssh / .gnupg paths", function()
  h.assert_false(security.is_safe_local_path("/home/alice/.ssh/id_rsa"))
  h.assert_false(security.is_safe_local_path("/home/bob/.gnupg/pubring.kbx"))
end)

h.test("rejects per-user .aws / .docker / .kube (defence-in-depth)", function()
  h.assert_false(security.is_safe_local_path("/home/alice/.aws/credentials"))
  h.assert_false(security.is_safe_local_path("/home/bob/.docker/config.json"))
  h.assert_false(security.is_safe_local_path("/home/carol/.kube/config"))
end)

h.test("accepts a path inside cwd (realpath returns descendant)", function()
  -- Stub the shell calls: pwd returns /home/user/proj, realpath returns
  -- /home/user/proj/sub. h.with_mock restores cmd.exec even if the
  -- assertion fails, so a regression here cannot leak the mock to the
  -- next test.
  local cmd = require("cmd")
  h.with_mock(cmd, "exec",
    h.sequence({ "/home/user/proj\n", "/home/user/proj/sub\n" }),
    function()
      local ok = security.is_safe_local_path("./sub")
      h.assert_true(ok, "expected /home/user/proj/sub inside /home/user/proj to be safe")
    end)
end)

h.test("rejects a path that resolves OUTSIDE cwd", function()
  local cmd = require("cmd")
  h.with_mock(cmd, "exec",
    h.sequence({ "/home/user/proj\n", "/tmp/elsewhere\n" }),
    function()
      h.assert_false(security.is_safe_local_path("./somehow_outside"))
    end)
end)

h.test("rejects a path that realpath cannot resolve (returns INVALID)", function()
  local cmd = require("cmd")
  h.with_mock(cmd, "exec",
    h.sequence({ "/home/user/proj\n", "INVALID\n" }),
    function()
      h.assert_false(security.is_safe_local_path("./bogus"))
    end)
end)

h.test("rejects when pwd subprocess fails (returns nil/empty)", function()
  local cmd = require("cmd")
  h.with_mock(cmd, "exec", function() return nil end, function()
    h.assert_false(security.is_safe_local_path("./foo"))
  end)
end)
