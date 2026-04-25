-- SPDX-License-Identifier: Apache-2.0
-- Copyright (c) 2024 Jose Badeau (https://github.com/jbadeau/mise-nix)
-- Modifications: Copyright (c) 2026 Ghislain LE MEUR

-- Build orchestration for nixhub and flake references
local version = require("version")
local platform = require("platform")
local flake = require("flake")
local shell = require("shell")
local logger = require("logger")

local M = {}

-- Build a package from nixhub metadata
function M.from_nixhub(tool, requested_version, current_os, current_arch)
  local start_time = os.time()
  logger.debug("Starting nixhub resolution for " .. tool .. "@" .. (requested_version or "latest"))

  -- Resolve version to actual release
  local release = version.resolve_version(tool, requested_version, current_os, current_arch)
  logger.debug(string.format("Version resolution took %ds", os.time() - start_time))
  
  -- Get platform build info
  local platform_build = release.platforms and release.platforms[1]
  if not platform_build then
    error("No platform build found for version " .. release.version)
  end

  -- Build Nix flake reference
  local repo_url = platform.get_nixpkgs_repo_url()
  local repo_ref = repo_url:gsub("https://github.com/", "github:")
  local flake_ref = string.format("%s/%s#%s", repo_ref, platform_build.commit_hash, platform_build.attribute_path)

  logger.step(string.format("Installing %s@%s...", tool, release.version))

  local env_prefix = platform.get_env_prefix()
  local impure_flag = platform.get_impure_flag()
  -- shquote the flake_ref so apostrophes / backticks / $() in an upstream
  -- commit or attribute path can't break out of the quoted word. Matches the
  -- convention used in flake.lua::build.
  local build_cmd = string.format("%snix build %s--no-link --print-out-paths %s", env_prefix, impure_flag, shell.shquote(flake_ref))

  local build_start = os.time()
  logger.debug("Starting nix build: " .. build_cmd)
  logger.info("Resolving package...")
  local build_output = shell.exec(build_cmd)
  logger.debug(string.format("Nix build took %ds", os.time() - build_start))

  local outputs = {}
  for path in build_output:gmatch("[^\n]+") do
    table.insert(outputs, path)
  end

  if #outputs == 0 then
    error("No outputs returned by nix build")
  end

  return {
    tool = tool,
    version = release.version,
    outputs = outputs,
    flake_ref = flake_ref
  }
end

-- Build a package from flake reference.
-- `version` on the returned descriptor is meant to stay consistent with the
-- nixhub path (release.version, a semver-like string). `built_ref` is a full
-- flake URL with a pinned revision -- it belongs in flake_ref, not version.
function M.from_flake(flake_ref, version_hint)
  local outputs, built_ref = flake.build(flake_ref, version_hint)

  return {
    flake_ref = built_ref,
    version = (version_hint and version_hint ~= "" and version_hint) or "flake",
    outputs = outputs,
  }
end

-- Choose best output path from build results
function M.choose_best_output(outputs, context_label)
  local chosen_path, has_binaries = platform.choose_store_path_with_bin(outputs)
  
  if not has_binaries then
    if context_label and context_label:match("vscode%-extensions%.") then
      logger.pack("VSCode extension package (no CLI binaries expected)")
    elseif context_label and context_label:match("vimPlugins%.") then
      logger.pack("Neovim plugin package (no CLI binaries expected)")
    else
      logger.warn("No binaries found. This package may be a library or data-only.")
      logger.hint("Using first available output for symlinking or build environment use.")
    end
  end
  
  return chosen_path
end

return M