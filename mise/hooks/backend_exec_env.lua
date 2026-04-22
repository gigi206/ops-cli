-- SPDX-License-Identifier: Apache-2.0
-- Copyright (c) 2024 Jose Badeau (https://github.com/jbadeau/mise-nix)
-- Modifications: Copyright (c) 2026 Ghislain LE MEUR

function PLUGIN:BackendExecEnv(ctx)
  local cmd = require("cmd")
  local shell = require("shell")
  local ip = shell.shquote(ctx.install_path)

  -- Resolve symlinks to get the actual nix store path
  local real_path = cmd.exec("readlink -f " .. ip .. " 2>/dev/null || echo " .. ip):gsub("\n", "")

  -- Check if the resolved path has a bin directory
  local bin_path = real_path .. "/bin"
  local has_bin = cmd.exec("test -d " .. shell.shquote(bin_path) .. " && echo yes || echo no"):match("yes")


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
