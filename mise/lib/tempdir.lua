-- SPDX-License-Identifier: Apache-2.0
-- Copyright (c) 2024 Jose Badeau (https://github.com/jbadeau/mise-nix)
-- Modifications: Copyright (c) 2026 Ghislain LE MEUR

-- Simple temporary directory management using native modules.
-- Uses mktemp -d (unpredictable names, atomic creation) instead of
-- os.time()+math.random, which has two issues: math.random is not seeded
-- (same sequence each process) and the path is predictable, allowing a
-- symlink-race attack between the mkdir and later writes.
local cmd = require("cmd")

local M = {}

-- Single-quote a value for safe inclusion in a shell command line.
-- Mirrors shell.shquote but kept local to avoid a require cycle with modules
-- that pull in tempdir.
local function shquote(s)
  return "'" .. tostring(s or ""):gsub("'", "'\\''") .. "'"
end

-- Create a unique temporary directory.
-- Callers are responsible for removing the directory when done (prefer
-- with_temp_dir which handles cleanup automatically).
function M.create_temp_dir(prefix)
  prefix = prefix or "mise_temp"
  local temp_base = os.getenv("TMPDIR") or "/tmp"
  -- Sanitize prefix: mktemp template must not contain slashes and the
  -- trailing XXXXXX is expanded by mktemp itself.
  local safe_prefix = prefix:gsub("[^%w._-]", "_")
  local template = temp_base .. "/" .. safe_prefix .. "_XXXXXXXX"
  local out = cmd.exec("mktemp -d " .. shquote(template))
  local temp_dir = (out or ""):gsub("%s+$", "")
  if temp_dir == "" then
    error("mktemp failed to create a temporary directory under " .. temp_base)
  end
  return temp_dir
end

-- Refuse to recursively delete anything outside a short list of temp bases.
-- Guards against TMPDIR=/ or a prefix injection crafting an absolute path.
local function is_safe_temp_path(path)
  if not path or path == "" or path == "/" then return false end
  local bases = { os.getenv("TMPDIR"), "/tmp", "/var/tmp" }
  for _, base in ipairs(bases) do
    if base and base ~= "" and base ~= "/" then
      -- Must be strictly under base (base + "/" + something).
      if path:sub(1, #base + 1) == base .. "/" then
        return true
      end
    end
  end
  return false
end

-- Execute `func(temp_dir)` and remove the directory afterwards — even when
-- `func` raises. Preserves all return values from `func`.
function M.with_temp_dir(prefix, func)
  local temp_dir = M.create_temp_dir(prefix)
  local results = table.pack(pcall(func, temp_dir))
  if is_safe_temp_path(temp_dir) then
    pcall(function() cmd.exec("rm -rf -- " .. shquote(temp_dir)) end)
  end
  if not results[1] then
    error(results[2])
  end
  return table.unpack(results, 2, results.n)
end

return M
