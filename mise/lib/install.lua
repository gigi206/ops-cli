-- SPDX-License-Identifier: Apache-2.0
-- Copyright (c) 2024 Jose Badeau (https://github.com/jbadeau/mise-nix)
-- Modifications: Copyright (c) 2026 Ghislain LE MEUR

-- Installation strategies for different package types
local platform = require("platform")
local vsix = require("vsix")
local vscode = require("vscode")
local jetbrains = require("jetbrains")
local neovim = require("neovim")
local shell = require("shell")
local logger = require("logger")

local M = {}

-- Register the store path as a Nix GC root so `nix-collect-garbage -d` does
-- not delete the binaries mise just installed. Without this, symlinks under
-- ~/.local/share/mise/installs/nix-*/<ver>/ become dangling after GC.
local function register_gc_root(store_path, install_path)
  local gc_dir = "/nix/var/nix/gcroots/mise"
  shell.try_exec("mkdir -p " .. shell.shquote(gc_dir) .. " 2>/dev/null")
  -- Root name = last two install_path segments joined, sanitised
  local segs = install_path:match("([^/]+/[^/]+)$") or install_path
  local rootname = segs:gsub("/", "-"):gsub("[^%w%-_.]", "_")
  shell.try_exec("ln -sfn " .. shell.shquote(store_path) .. " " .. shell.shquote(gc_dir .. "/" .. rootname))
end

-- Escape a Lua pattern so magic characters in a store path like
-- `/nix/store/abc-def-1.2.3` (contains `-` and `.`) match literally.
local function _escape_pattern(s)
  return (s:gsub("([%^%$%(%)%%%.%[%]%*%+%-%?])", "%%%1"))
end

-- Standard tool installation via symlink (PVC-optimized)
function M.standard_tool(nix_store_path, install_path, label)
  logger.tool("Installing as standard tool: " .. label)

  -- In containerized environments, check if symlink already exists and is correct
  if shell.is_containerized() then
    local ok, current_target = shell.try_exec("readlink " .. shell.shquote(install_path) .. " 2>/dev/null")
    if ok and current_target and current_target:match(_escape_pattern(nix_store_path) .. "$") then
      logger.debug("Symlink already correct: " .. install_path)
      register_gc_root(nix_store_path, install_path)
      return
    end
  end

  shell.symlink_force(nix_store_path, install_path)
  register_gc_root(nix_store_path, install_path)
end

-- Flake installation with hash workaround for direct references (PVC-optimized)
function M.flake_with_hash_workaround(nix_store_path, install_path)
  -- WORKAROUND: mise expects a directory named after the nix store hash for direct flake references
  local nix_hash = nix_store_path:match("/nix/store/([^/]+)")
  if not nix_hash then return end
  
  local install_dir = install_path:match("^(.+)/[^/]+$")
  if not install_dir then return end
  
  local hash_path = install_dir .. "/" .. nix_hash
  
  -- In containerized environments, check if target already points correctly to avoid unnecessary I/O
  if shell.is_containerized() then
    local ok, current_target = shell.try_exec("readlink " .. shell.shquote(hash_path) .. " 2>/dev/null")
    if ok and current_target and current_target:match(_escape_pattern(nix_store_path) .. "$") then
      logger.debug("Hash symlink already correct: " .. hash_path)
      return
    end
  end
  
  shell.symlink_force(nix_store_path, hash_path)
end

-- Install from nixhub with automatic version resolution
function M.from_nixhub(tool, requested_version, install_path)
  local current_os = platform.normalize_os(RUNTIME.osType)
  -- RUNTIME.archType is vfox-native ("amd64" / "arm64"); pass it through
  -- unchanged. Do NOT normalize to nix-system names ("x86_64" / "aarch64")
  -- here -- version.is_compatible matches nixhub platforms_summary strings
  -- which use the vfox form.
  local current_arch = RUNTIME.archType and RUNTIME.archType:lower() or ""
  
  local build_result = vsix.from_nixhub(tool, requested_version, current_os, current_arch)
  local nix_store_path = vsix.choose_best_output(build_result.outputs, tool)
  
  -- Verify the build succeeded
  platform.verify_build(nix_store_path, tool)

  -- Handle VSCode extensions and JetBrains plugins specially
  if vscode.is_extension(tool) then
    vscode.install_extension(nix_store_path, tool)
  elseif jetbrains.is_plugin(tool) then
    jetbrains.install_plugin_from_store(nix_store_path, tool)
  else
    M.standard_tool(nix_store_path, install_path, tool)
  end

  logger.done(string.format("Successfully installed %s@%s", tool, build_result.version))
  
  return {
    version = build_result.version,
    store_path = nix_store_path,
    is_vscode = vscode.is_extension(tool),
    is_jetbrains = jetbrains.is_plugin(tool)
  }
end

-- Install from flake reference
function M.from_flake(flake_ref, version_hint, install_path)
  local build_result = vsix.from_flake(flake_ref, version_hint)
  local nix_store_path = vsix.choose_best_output(build_result.outputs, flake_ref)
  
  -- Verify the build succeeded
  platform.verify_build(nix_store_path, flake_ref)

  local is_vscode = vscode.is_extension(flake_ref)
  local is_jetbrains = jetbrains.is_plugin(flake_ref)
  local is_neovim = neovim.is_plugin(flake_ref)

  if is_vscode then
    logger.find("Detected VSCode extension flake: " .. flake_ref)
    vscode.install_extension(nix_store_path, flake_ref)
  elseif is_jetbrains then
    logger.find("Detected JetBrains plugin flake: " .. flake_ref)
    jetbrains.install_plugin_from_store(nix_store_path, flake_ref)
  elseif is_neovim then
    neovim.install_plugin_from_store(nix_store_path, flake_ref)
  else
    M.standard_tool(nix_store_path, install_path, flake_ref)
    M.flake_with_hash_workaround(nix_store_path, install_path)
  end

  logger.done("Successfully installed " .. build_result.version)

  return {
    version = build_result.version,
    store_path = nix_store_path,
    is_vscode = is_vscode,
    is_jetbrains = is_jetbrains,
    is_neovim = is_neovim
  }
end

return M