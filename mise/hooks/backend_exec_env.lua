-- SPDX-License-Identifier: Apache-2.0
-- Copyright (c) 2024 Jose Badeau (https://github.com/jbadeau/mise-nix)
-- Modifications: Copyright (c) 2026 Ghislain LE MEUR

function PLUGIN:BackendExecEnv(ctx)
  local cmd = require("cmd")
  local shell = require("shell")
  local ip = shell.shquote(ctx.install_path)

  -- Resolve symlinks to get the actual nix store path.
  -- cmd.exec can return nil on failure; fall back to the original path rather
  -- than crashing on :gsub.
  local resolved = cmd.exec("readlink -f " .. ip .. " 2>/dev/null || echo " .. ip) or ctx.install_path
  local real_path = resolved:gsub("\n", "")

  -- Check if the resolved path has a bin directory
  local bin_path = real_path .. "/bin"
  local bin_check = cmd.exec("test -d " .. shell.shquote(bin_path) .. " && echo yes || echo no") or ""
  local has_bin = bin_check:match("yes")


  if has_bin then
    return {
      env_vars = {
        { key = "PATH", value = bin_path }
      }
    }
  else
    -- Fallback to the original logic if no bin directory found
    return {
      env_vars = {
        { key = "PATH", value = ctx.install_path .. "/bin" }
      }
    }
  end
end
