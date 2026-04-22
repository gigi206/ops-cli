-- SPDX-License-Identifier: Apache-2.0
-- Copyright (c) 2026 Ghislain LE MEUR

-- Shared helpers for editor-plugin detection and identifier extraction.
-- Removes the duplicated `if not tool_name then return` / multi-pattern
-- match boilerplate that used to live in vscode.lua, jetbrains.lua and
-- neovim.lua. Callers pass one or more Lua patterns; the first match wins.

local M = {}

-- True if `tool_name` is a non-nil string that matches any of the given
-- Lua patterns.
function M.matches(tool_name, ...)
  if not tool_name or type(tool_name) ~= "string" then return false end
  for i = 1, select("#", ...) do
    local pat = select(i, ...)
    if pat and tool_name:match(pat) then return true end
  end
  return false
end

-- Returns the first capture group produced by any of the given patterns on
-- `tool_or_flake`, or nil if none matches (or if input is nil).
function M.extract(tool_or_flake, ...)
  if not tool_or_flake or type(tool_or_flake) ~= "string" then return nil end
  for i = 1, select("#", ...) do
    local pat = select(i, ...)
    if pat then
      local captured = tool_or_flake:match(pat)
      if captured then return captured end
    end
  end
  return nil
end

return M
