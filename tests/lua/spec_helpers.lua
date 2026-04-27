-- Shared bootstrap for the Lua unit tests under tests/lua/.
--
-- The plugin modules `require` mise's native modules (`cmd`, `file`, `log`,
-- `json`, `strings`, `http`) which only exist when the plugin runs inside
-- a real mise host. To exercise the pure-Lua helpers (string parsing,
-- pattern matching, quoting) under a stock `lua`, we install minimal
-- in-process stubs via package.preload BEFORE the modules under test
-- pull them in.
--
-- Each stub is intentionally trivial. Tests that need richer behaviour
-- can monkey-patch the returned table after `require`'ing the module
-- under test, e.g.:
--   local shell = require_module("shell")
--   local cmd = require("cmd")
--   cmd.exec = function() return "yes\n" end

local M = {}

-- Resolve the plugin source tree relative to this helper. The harness
-- typically runs `lua tests/lua/run.lua` from the repo root, so we anchor
-- the lookup to `tests/lua/`.
local function plugin_root()
  local here = debug.getinfo(1, "S").source:sub(2)  -- strip leading "@"
  -- here = ".../tests/lua/spec_helpers.lua"
  local dir = here:match("^(.*)/[^/]+$") or "."
  -- dir = ".../tests/lua"
  return dir .. "/../../mise"
end

local root = plugin_root()
package.path = root .. "/lib/?.lua;" .. root .. "/?.lua;" .. package.path

-- ---------------------------------------------------------------------------
-- Stubs for mise's native modules.
-- ---------------------------------------------------------------------------

-- exec ignores its argument(s) and returns whatever the test set via
-- fake_cmd._next (default ""). Works whether the caller uses dot
-- notation `cmd.exec("foo")` or colon form `cmd:exec("foo")` — both
-- pass through `...` and we ignore them.
local fake_cmd = { _next = "" }
fake_cmd.exec = function(...) return fake_cmd._next or "" end

local fake_file = {
  exists    = function(_) return false end,
  join_path = function(...) return (table.concat({...}, "/"):gsub("/+", "/")) end,
  read      = function(_) return "" end,
  symlink   = function(_, _) end,
}

local fake_log = {
  trace = function(...) end,
  debug = function(...) end,
  info  = function(...) end,
  warn  = function(...) end,
  error = function(...) end,
}

local fake_json = {
  encode = function(v) return tostring(v) end,
  decode = function(s) return nil end,
}

local fake_strings = {
  contains   = function(s, sub) return s:find(sub, 1, true) ~= nil end,
  has_prefix = function(s, p)   return s:sub(1, #p) == p end,
  has_suffix = function(s, p)   return p == "" or s:sub(-#p) == p end,
  join       = function(t, sep) return table.concat(t, sep) end,
  split      = function(s, sep)
    local out = {}
    if sep == "" then for c in s:gmatch(".") do out[#out+1] = c end; return out end
    local pat = "([^" .. sep:gsub("[%(%)%.%%%+%-%*%?%[%]%^%$]", "%%%1") .. "]+)"
    for w in s:gmatch(pat) do out[#out+1] = w end
    return out
  end,
  trim       = function(s, suf)
    if suf == "" then return s end
    -- Escape Lua-pattern magic chars in `suf` so a literal "." isn't
    -- interpreted as "any char" (mirrors mise's native strings.trim, which
    -- treats `suf` as a literal string, not a pattern).
    local esc = suf:gsub("([%^%$%(%)%%%.%[%]%*%+%-%?])", "%%%1")
    return (s:gsub(esc .. "$", ""))
  end,
  trim_space = function(s) return (s:gsub("^%s+", ""):gsub("%s+$", "")) end,
}

local fake_http = {
  get = function(_) return nil, "stubbed" end,
}

package.preload["cmd"]     = function() return fake_cmd end
package.preload["file"]    = function() return fake_file end
package.preload["log"]     = function() return fake_log end
package.preload["json"]    = function() return fake_json end
package.preload["strings"] = function() return fake_strings end
package.preload["http"]    = function() return fake_http end

-- Expose the stubs so individual tests can override behaviour.
M.cmd     = fake_cmd
M.file    = fake_file
M.log     = fake_log
M.json    = fake_json
M.strings = fake_strings
M.http    = fake_http

-- ---------------------------------------------------------------------------
-- Tiny test harness (no busted dependency).
-- ---------------------------------------------------------------------------

M.passed = 0
M.failed = 0
M.failures = {}

function M.test(name, body)
  local ok, err = pcall(body)
  if ok then
    M.passed = M.passed + 1
    io.write("  ok  ", name, "\n")
  else
    M.failed = M.failed + 1
    M.failures[#M.failures+1] = name .. " -- " .. tostring(err)
    io.write("  FAIL ", name, "\n        ", tostring(err), "\n")
  end
end

function M.assert_eq(actual, expected, msg)
  if actual ~= expected then
    error((msg or "values differ") ..
      "\n        expected: " .. tostring(expected) ..
      "\n        actual:   " .. tostring(actual), 2)
  end
end

function M.assert_true(cond, msg)
  if not cond then error(msg or "expected truthy", 2) end
end

function M.assert_false(cond, msg)
  if cond then error(msg or "expected falsy", 2) end
end

-- ---------------------------------------------------------------------------
-- Mock helpers — restore-on-failure.
-- ---------------------------------------------------------------------------
--
-- The naive pattern
--     local saved = target.x; target.x = mock; ...assertions...; target.x = saved
-- leaks the mock to the next test on assertion failure (the restore line is
-- never reached). The helpers below wrap the body in pcall so the original
-- value is restored even when an assertion or runtime error fires.

-- Replace `target[key]` with `replacement` for the duration of `body()`.
-- Restores the original value on both happy path and exception path, then
-- re-raises any captured error so the test still fails.
function M.with_mock(target, key, replacement, body)
  local saved = target[key]
  target[key] = replacement
  local ok, err = pcall(body)
  target[key] = saved
  if not ok then error(err, 2) end
end

-- Same as with_mock but for several mocks at once. Pass a list of
-- {target, key, replacement} triples. All are installed before body()
-- runs and unconditionally restored after, in reverse order.
function M.with_mocks(mocks, body)
  local saved = {}
  for i, m in ipairs(mocks) do
    saved[i] = m[1][m[2]]
    m[1][m[2]] = m[3]
  end
  local ok, err = pcall(body)
  for i = #mocks, 1, -1 do
    mocks[i][1][mocks[i][2]] = saved[i]
  end
  if not ok then error(err, 2) end
end

-- Build a function that returns the i-th element of `responses` on the i-th
-- call, then "" once exhausted. Useful for stubbing cmd.exec when a test
-- needs distinct stdout values for several successive calls.
--   cmd.exec = h.sequence({"/home/u/proj\n", "/home/u/proj/sub\n"})
function M.sequence(responses)
  local idx = 0
  return function()
    idx = idx + 1
    return responses[idx] or ""
  end
end

return M
