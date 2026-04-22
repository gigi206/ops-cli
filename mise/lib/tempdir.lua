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

-- Create a unique temporary directory (no cleanup needed).
function M.create_temp_dir(prefix)
  prefix = prefix or "mise_temp"
  local temp_base = os.getenv("TMPDIR") or "/tmp"
  -- Sanitize prefix: mktemp template must not contain slashes and the
  -- trailing XXXXXX is expanded by mktemp itself.
  local safe_prefix = prefix:gsub("[^%w._-]", "_")
  local template = temp_base .. "/" .. safe_prefix .. "_XXXXXXXX"
  local out = cmd.exec("mktemp -d '" .. template:gsub("'", "'\\''") .. "'")
  local temp_dir = (out or ""):gsub("%s+$", "")
  if temp_dir == "" then
    error("mktemp failed to create a temporary directory under " .. temp_base)
  end
  return temp_dir
end

-- Execute function with temp directory (no cleanup)
function M.with_temp_dir(prefix, func)
  local temp_dir = M.create_temp_dir(prefix)
  return func(temp_dir)
end

return M