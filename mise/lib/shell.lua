-- SPDX-License-Identifier: Apache-2.0
-- Copyright (c) 2024 Jose Badeau (https://github.com/jbadeau/mise-nix)
-- Modifications: Copyright (c) 2026 Ghislain LE MEUR

-- Shell execution utilities with better error handling
local cmd = require("cmd")  -- Native mise cmd module
local file = require("file")  -- Native mise file module

local M = {}

-- Quote a string for safe inclusion inside a single-quoted shell word:
-- wraps the value in single quotes and escapes embedded ' as '\''.
-- Use whenever a variable is concatenated into a shell command string.
function M.shquote(s)
  return "'" .. tostring(s or ""):gsub("'", "'\\''") .. "'"
end

-- Escape Lua-pattern magic characters in a string so it can be used as a
-- literal anchor inside another pattern. Necessary when matching paths that
-- contain `-`, `.`, `[`, `+`, `(`, etc. — a Nix store path like
-- `/nix/store/abc-def-1.2.3` would otherwise be interpreted by Lua's match
-- engine as containing alternation/quantifier metacharacters.
function M.escape_pattern(s)
  return (tostring(s or ""):gsub("([%^%$%(%)%%%.%[%]%*%+%-%?])", "%%%1"))
end

-- Test whether `path` exists (kind = "f" file, "d" directory, "e" exists).
-- Replacement for the buggy idiom `shell.try_exec("test -f " .. path)`:
-- mise's `cmd.exec` swallows non-zero exit codes and always returns stdout,
-- so the boolean returned by try_exec is true regardless of the test outcome
-- (it only reflects pcall success). We probe stdout for an explicit `yes`
-- marker instead, which the shell only prints when the test succeeded.
function M.path_exists(path, kind)
  local k = kind or "e"
  local cmd_str = "test -" .. k .. " " .. M.shquote(path) .. " && echo yes"
  local ok, out = M.try_exec(cmd_str)
  if not ok then return false end
  if type(out) ~= "string" then return false end
  return out:match("yes") ~= nil
end

-- Execute shell command with formatted arguments
function M.exec(fmt, ...)
  local command = (select("#", ...) > 0) and string.format(fmt, ...) or fmt
  return cmd.exec(command)
end

-- Try to execute shell command, return success status and result
function M.try_exec(fmt, ...)
  local args = {...}
  local unpack = table.unpack or unpack  -- Compatibility with Lua 5.1/5.2
  local ok, result = pcall(function() 
    return M.exec(fmt, unpack(args))
  end)
  return ok, result
end

-- Force create symlink using native file module
function M.symlink_force(src, dst)
  -- Remove target first if it exists, then create the new symlink.
  -- Quote the destination path with shquote() so paths containing spaces,
  -- quotes, backticks, or `$(...)` cannot break out of the `rm -rf` command
  -- line. The previous form ('rm -rf "%s"', dst) only protected against
  -- simple cases.
  M.try_exec("rm -rf " .. M.shquote(dst))
  file.symlink(src, dst)
end

-- Batch create multiple symlinks
function M.symlink_batch(operations)
  if not operations or #operations == 0 then return end

  for _, op in ipairs(operations) do
    M.symlink_force(op.src, op.dst)
  end
end

-- Check if running in containerized environment (K8s/PVC).
-- /.dockerenv presence is probed via path_exists rather than try_exec("test -f"):
-- try_exec returns (ok, stdout) and ok is the pcall-success boolean — true even
-- when `test -f` exits non-zero (cmd.exec swallows non-zero codes). Using the
-- boolean directly in `or` made this function return true on every host.
function M.is_containerized()
  return os.getenv("KUBERNETES_SERVICE_HOST") ~= nil or
         os.getenv("CONTAINER") ~= nil or
         M.path_exists("/.dockerenv", "f")
end

return M