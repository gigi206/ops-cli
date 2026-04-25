-- SPDX-License-Identifier: MIT
-- Copyright (c) 2024 Josh Bode (https://github.com/mise-plugins/mise-nix)

local utils = require("utils")

---@type Strings
local strings = require("strings")

function PLUGIN.MisePath(_, ctx)
  local options = ctx.options
  if options == false then
    return {}
  elseif options == true then
    options = {}
  end

  local path = os.getenv("MISE_NIX_PATH")

  if path ~= nil then
    return strings.split(path, ":")
  end

  ---@cast options Options
  -- MisePath silently ignores load_env diagnostics. MiseEnv is the sole
  -- source of user-facing error output (see hooks/mise_env.lua). This is
  -- what guarantees each diagnostic appears exactly once per `mise env`
  -- invocation, even though mise calls both hooks in separate processes.
  local result = utils.load_env(options)
  if result == nil then
    return {}
  end

  for key, info in pairs(result.env.variables) do
    if key == "PATH" then
      return strings.split(info.value, ":")
    end
  end

  return {}
end
