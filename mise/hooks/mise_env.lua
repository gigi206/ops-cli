-- SPDX-License-Identifier: MIT
-- Copyright (c) 2024 Josh Bode (https://github.com/mise-plugins/mise-nix)

local utils = require("utils")

---@type Log
local log = require("log")

---@dictionary "ignore" | "keep"
local VARS = {
  HOME = "ignore",
  SHELL = "ignore",
  TERM = "ignore",
  TMPDIR = "ignore",
  TZ = "ignore",
}

function PLUGIN.MiseEnv(_, ctx)
  local options = ctx.options
  if options == false then
    return {}
  elseif options == true then
    options = {}
  end

  ---@cast options Options
  -- MiseEnv is the hook responsible for surfacing load_env diagnostics
  -- to the user. MisePath calls load_env too, but silently -- that is
  -- how we dedupe messages: mise runs each hook in its own Lua process,
  -- so module-level flags can't bridge them.
  local result, errs = utils.load_env(options)
  if result == nil then
    if errs then
      for _, line in ipairs(errs) do log.error(line) end
    end
    return {}
  end

  ---@type { key: string, value: string}[]
  local env = {}

  for key, info in pairs(result.env.variables) do
    ---@diagnostic disable-next-line: unnecessary-if
    if VARS[key] == "ignore" then
      -- skip
    elseif key == "PATH" then
      -- cache for path handler
      env[#env + 1] = { key = "MISE_NIX_PATH", value = info.value }
    elseif info.type == "exported" then
      env[#env + 1] = { key = key, value = info.value }
    end
  end

  return {
    cacheable = true,
    watch_files = { result.lock_file },
    env = env,
  }
end
