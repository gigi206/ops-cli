local h = require("spec_helpers")
local utils = require("utils")

io.write("== utils.cache (devenv disk cache) ==\n")

-- Helpers ---------------------------------------------------------------------

-- Allocate a fresh tmp dir per test (no parallelism issues, easy cleanup).
local function fresh_tmp_dir()
  local base = os.getenv("TMPDIR") or "/tmp"
  local name = string.format("test_utils_cache_%d_%d", os.time(), math.random(1, 1e9))
  local dir = base .. "/" .. name
  os.execute("mkdir -p '" .. dir .. "'")
  return dir
end

local function rm_rf(dir)
  if dir and dir:sub(1, 5) == "/tmp/" then
    os.execute("rm -rf '" .. dir .. "'")
  end
end

local function write_file(path, content)
  local f = assert(io.open(path, "w"))
  f:write(content)
  f:close()
end

local function read_file(path)
  local f = io.open(path, "r")
  if not f then return nil end
  local c = f:read("*a")
  f:close()
  return c
end

-- compute_cache_key -----------------------------------------------------------

h.test("compute_cache_key returns 16 hex chars when sha256sum cooperates", function()
  -- Stub cmd.exec to return a predictable sha256 line. compute_cache_key
  -- only needs the first 16 hex chars after trim, so any trailing newline
  -- or whitespace is fine.
  h.cmd._next = "deadbeefcafebabe\n"
  local key = utils._compute_cache_key("/tmp/p", ".#default", "default")
  h.assert_eq(key, "deadbeefcafebabe")
end)

h.test("compute_cache_key returns nil on non-hex output", function()
  h.cmd._next = "not-a-hash\n"
  local key = utils._compute_cache_key("/tmp/p", ".#default", "default")
  h.assert_eq(key, nil)
end)

h.test("compute_cache_key rejects wrong length", function()
  h.cmd._next = "deadbeef\n"  -- only 8 chars, expected 16
  local key = utils._compute_cache_key("/tmp/p", ".#default", "default")
  h.assert_eq(key, nil)
end)

h.test("compute_cache_key returns nil when cmd.exec returns nothing", function()
  h.cmd._next = ""
  local key = utils._compute_cache_key("/tmp/p", ".#default", "default")
  h.assert_eq(key, nil)
end)

-- save_to_cache + load_from_cache (real disk I/O) -----------------------------

h.test("save_to_cache writes JSON and load_from_cache reads it back", function()
  local dir = fresh_tmp_dir()
  -- The fake_json stub in spec_helpers returns nil from decode and tostring()
  -- from encode. To exercise the real round-trip we replace it with a tiny
  -- deterministic encoder/decoder pair. h.with_mocks restores all four
  -- targets even if an assertion fails midway, then rm_rf runs in the
  -- always-after block below.
  local ok, err = pcall(function()
    h.with_mocks({
      { h.json, "encode", function(v)
          if type(v) ~= "table" then return tostring(v) end
          local k, val = next(v)
          return string.format([[{"%s":"%s"}]], tostring(k), tostring(val))
        end },
      { h.json, "decode", function(s)
          local k, val = s:match([[%{"([^"]+)":"([^"]*)"%}]])
          if not k then return nil end
          return { [k] = val }
        end },
      { h.file, "exists", function(p)
          local f = io.open(p, "r")
          if f then f:close(); return true end
          return false
        end },
      -- load_from_cache probes the profile dir for a live nix gc-root via
      -- shell.path_exists (test -e + "yes" marker). For non-test commands
      -- (mv inside save_to_cache) shell out for real.
      { h.cmd, "exec", function(c)
          if c:find("test %-e") then return "yes\n" end
          os.execute(c .. " >/dev/null 2>&1")
          return ""
        end },
    }, function()
      local cache_file = dir .. "/cache.json"
      utils._save_to_cache(cache_file, { hello = "world" })

      local loaded = utils._load_from_cache(cache_file, dir)
      h.assert_true(loaded ~= nil, "expected loaded value, got nil")
      h.assert_eq(loaded.hello, "world")
    end)
  end)
  rm_rf(dir)
  if not ok then error(err, 2) end
end)

h.test("load_from_cache returns nil when file is absent", function()
  local loaded = utils._load_from_cache("/nonexistent/path/cache.json", "/nonexistent")
  h.assert_eq(loaded, nil)
end)

h.test("load_from_cache returns nil when nix profile gc-root is missing", function()
  local dir = fresh_tmp_dir()
  local cache_file = dir .. "/cache.json"
  write_file(cache_file, "{}")

  local ok, err = pcall(function()
    h.with_mocks({
      { h.file, "exists", function(p)
          local f = io.open(p, "r"); if f then f:close(); return true end; return false
        end },
      -- Probe returns empty (no "yes") -> simulate a profile symlink whose
      -- target was gc-collected. Cache must be invalidated.
      { h.cmd, "exec", function(_) return "" end },
    }, function()
      local loaded = utils._load_from_cache(cache_file, dir)
      h.assert_eq(loaded, nil, "stale-store cache should not load")
    end)
  end)
  rm_rf(dir)
  if not ok then error(err, 2) end
end)

h.test("load_from_cache returns nil on corrupted JSON", function()
  local dir = fresh_tmp_dir()
  local cache_file = dir .. "/cache.json"
  write_file(cache_file, "not-json-at-all")

  local ok, err = pcall(function()
    h.with_mocks({
      { h.file, "exists", function(p)
          local f = io.open(p, "r"); if f then f:close(); return true end; return false
        end },
      { h.cmd, "exec", function(c)
          if c:find("test %-e") then return "yes\n" end
          return ""
        end },
    }, function()
      -- fake_json.decode returns nil for any input, simulating a parse failure.
      local loaded = utils._load_from_cache(cache_file, dir)
      h.assert_eq(loaded, nil)
    end)
  end)
  rm_rf(dir)
  if not ok then error(err, 2) end
end)

h.test("save_to_cache does not write when json.encode fails", function()
  local dir = fresh_tmp_dir()
  local cache_file = dir .. "/cache.json"

  local mv_calls = 0
  local ok, err = pcall(function()
    h.with_mocks({
      { h.json, "encode", function(_) error("encode failed", 0) end },
      { h.cmd, "exec", function(c)
          if c:match("^mv ") then mv_calls = mv_calls + 1 end
          return ""
        end },
    }, function()
      utils._save_to_cache(cache_file, { x = 1 })
      h.assert_eq(mv_calls, 0, "mv should not run when encode fails")
      h.assert_eq(read_file(cache_file), nil, "cache file should not exist after encode failure")
    end)
  end)
  rm_rf(dir)
  if not ok then error(err, 2) end
end)
