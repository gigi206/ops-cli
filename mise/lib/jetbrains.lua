-- SPDX-License-Identifier: Apache-2.0
-- Copyright (c) 2024 Jose Badeau (https://github.com/jbadeau/mise-nix)
-- Modifications: Copyright (c) 2026 Ghislain LE MEUR

-- JetBrains plugin detection, management, and installation
local shell = require("shell")
local logger = require("logger")
local platform = require("platform")
local plugin_matcher = require("plugin_matcher")

local M = {}

-- Plugin detection
function M.is_plugin(tool_name)
  return plugin_matcher.matches(tool_name,
    "^jetbrains%-plugins%.",
    "^jetbrains%+install=jetbrains%-plugins%.")
end

function M.extract_plugin_info(tool_or_flake)
  if not tool_or_flake then return nil end

  -- Extract from patterns like: jetbrains-plugins.x86_64-linux.idea-ultimate.2024.3.com.intellij.plugins.watcher
  -- or: jetbrains+install=jetbrains-plugins.x86_64-linux.idea-ultimate.2024.3.com.intellij.plugins.watcher
  -- The bespoke "parse system.ide.version.plugin_id" logic below stays
  -- inline -- plugin_matcher only factors out the two simple capture
  -- patterns that all three editor modules share.
  local pattern = plugin_matcher.extract(tool_or_flake,
    "jetbrains%-plugins%.(.+)",
    "^jetbrains%+install=jetbrains%-plugins%.(.+)")

  if not pattern then return nil end

  -- Parse the pattern: system.ide.version.plugin_id
  local parts = {}
  for part in pattern:gmatch("[^.]+") do
    table.insert(parts, part)
  end

  if #parts < 4 then return nil end

  -- Parse more carefully: system.ide.version.plugin_id
  -- Plugin IDs typically start with com., org., or are known patterns like jetbrains.
  local system = parts[1]  -- x86_64-linux
  local ide = parts[2]     -- idea-ultimate

  -- Find where plugin ID starts by looking for known plugin ID prefixes
  local plugin_start_idx = nil
  for i = 3, #parts do
    local part = parts[i]
    if part:match("^com$") or part:match("^org$") or part:match("^jetbrains$") or part:match("^intellij$") then
      plugin_start_idx = i
      break
    end
  end

  if not plugin_start_idx then
    -- If no known prefix found, look for patterns that don't look like version numbers
    for i = 3, #parts do
      local part = parts[i]
      -- If it's not a year-like number and not a single digit, it's probably the plugin ID
      if not part:match("^%d+$") and not part:match("^20%d%d$") then
        plugin_start_idx = i
        break
      end
    end
  end

  if not plugin_start_idx then
    -- Last resort: assume standard format system.ide.version.plugin_id
    plugin_start_idx = 4
  end

  -- Reconstruct version and plugin ID
  local version_parts = {}
  for i = 3, plugin_start_idx - 1 do
    table.insert(version_parts, parts[i])
  end
  local version = table.concat(version_parts, ".")

  local plugin_id_parts = {}
  for i = plugin_start_idx, #parts do
    table.insert(plugin_id_parts, parts[i])
  end
  local plugin_id = table.concat(plugin_id_parts, ".")

  return {
    system = system,
    ide = ide,
    version = version,
    plugin_id = plugin_id
  }
end


-- Directory management for different JetBrains IDEs
function M.get_plugins_dir(ide_name, version)
  local home = os.getenv("HOME")

  local ide_dirs = {
    ["idea-ultimate"] = "IntelliJIdea",
    ["idea-community"] = "IntelliJIdea",
    ["pycharm-professional"] = "PyCharm",
    ["pycharm-community"] = "PyCharmCE",
    ["webstorm"] = "WebStorm",
    ["phpstorm"] = "PhpStorm",
    ["rider"] = "Rider",
    ["clion"] = "CLion",
    ["goland"] = "GoLand",
    ["datagrip"] = "DataGrip",
    ["rubymine"] = "RubyMine",
    ["dataspell"] = "DataSpell"
  }

  local dir_name = ide_dirs[ide_name] or ide_name
  local os_type = platform.detect_os()

  if os_type == "macos" then
    -- macOS: ~/Library/Application Support/JetBrains/IntelliJIdea<version>/plugins
    return home .. "/Library/Application Support/JetBrains/" .. dir_name .. version .. "/plugins"
  else
    -- Linux: ~/.local/share/JetBrains/IntelliJIdea<version>/plugins
    return home .. "/.local/share/JetBrains/" .. dir_name .. version .. "/plugins"
  end
end

-- List all .jar files under `plugin_path`. Returns nil when the find
-- output is empty / whitespace-only — caller falls back to the dir layout.
local function list_jars(plugin_path)
  local ok, out = shell.try_exec("find " .. shell.shquote(plugin_path) .. ' -name "*.jar" -type f')
  if not ok or not out or not out:match("%S") then
    return nil
  end
  local jars = {}
  for jar_file in out:gmatch("[^\n]+") do
    table.insert(jars, jar_file)
  end
  return jars
end

-- Copy a single JAR into plugins_dir, skipping if already there.
-- Returns (true, name) on success, (false, err) on failure.
local function install_jar(jar_file, plugins_dir)
  local jar_name = jar_file:match("([^/]+)$")
  local target_path = plugins_dir .. "/" .. jar_name
  if shell.path_exists(target_path, "f") then
    logger.info("JetBrains plugin JAR already installed: " .. jar_name)
    return true, jar_name
  end
  local copy_ok, copy_result = shell.try_exec(
    "cp " .. shell.shquote(jar_file) .. " " .. shell.shquote(target_path))
  if copy_ok then
    logger.debug("Copied JAR: " .. jar_name)
    return true, jar_name
  end
  logger.fail("Failed to copy JAR: " .. jar_name)
  logger.debug("Copy error: " .. (copy_result or "unknown error"))
  return false, copy_result
end

-- JAR-tree branch: each *.jar lives directly under the plugins_dir.
-- Returns (ok, status) following the install_plugin contract below.
local function install_via_jars(plugin_path, plugin_info, plugins_dir)
  local jars = list_jars(plugin_path)
  if not jars then
    return nil, nil  -- caller will try the directory fallback
  end
  local jar_list = {}
  for _, jar_file in ipairs(jars) do
    local ok, name_or_err = install_jar(jar_file, plugins_dir)
    if not ok then
      return false, name_or_err
    end
    table.insert(jar_list, name_or_err)
  end
  if #jar_list == 0 then
    return nil, nil
  end
  logger.done("JetBrains plugin installed: " .. plugin_info.plugin_id)
  logger.info("Plugin JARs: " .. table.concat(jar_list, ", "))
  logger.info("Plugin location: " .. plugins_dir)
  logger.info("Restart your JetBrains IDE to activate the plugin")
  return true, "installed"
end

-- Directory-tree branch: plugin ships as a sub-directory tree (META-INF/,
-- lib/, etc.) under plugin_install_dir.
local function install_via_dir(plugin_path, plugin_info, plugin_install_dir)
  if shell.path_exists(plugin_install_dir, "d") then
    logger.info("JetBrains plugin already installed: " .. plugin_info.plugin_id)
    return true, "already_installed"
  end
  shell.exec("mkdir -p " .. shell.shquote(plugin_install_dir))

  -- Copy plugin files. The trailing /* and / are shell syntax, not part of
  -- the quoted path — we shquote the bases and concat the glob/suffix after.
  local copy_ok, copy_result = shell.try_exec(
    "cp -r " .. shell.shquote(plugin_path) .. "/* " .. shell.shquote(plugin_install_dir) .. "/")
  if copy_ok then
    logger.done("JetBrains plugin installed: " .. plugin_info.plugin_id)
    logger.info("Plugin location: " .. plugin_install_dir)
    logger.info("Restart your JetBrains IDE to activate the plugin")
    return true, "installed"
  end
  logger.fail("JetBrains plugin installation failed")
  logger.debug("Copy error: " .. (copy_result or "unknown error"))
  -- Clean up failed installation
  shell.try_exec("rm -rf " .. shell.shquote(plugin_install_dir))
  return false, copy_result
end

-- Plugin installation via extracted JAR/ZIP. Two-branch flow:
--   1. JAR tree    — *.jar files copied flat into plugins_dir
--   2. Directory   — full sub-tree copied under plugins_dir/<plugin_id>/
-- The branches are split into helpers above so the orchestration here
-- stays readable. Returns (ok, status_string).
function M.install_plugin(plugin_path, plugin_info)
  -- In CI environments, skip actual JetBrains plugin installation since it's experimental
  if os.getenv("CI") or os.getenv("GITHUB_ACTIONS") then
    logger.info("Skipping JetBrains plugin installation in CI environment")
    logger.info("JetBrains plugin functionality is experimental and not reliable in headless CI")
    return true, "skipped_in_ci"
  end

  local plugins_dir = M.get_plugins_dir(plugin_info.ide, plugin_info.version)
  logger.debug("Detected OS: " .. platform.detect_os())
  logger.debug("Plugin directory: " .. plugins_dir)
  shell.exec("mkdir -p " .. shell.shquote(plugins_dir))

  -- Try the JAR-tree layout first; install_via_jars returns nil when no
  -- JARs are present, signalling we should fall through to the dir layout.
  local jar_ok, jar_status = install_via_jars(plugin_path, plugin_info, plugins_dir)
  if jar_ok ~= nil then
    return jar_ok, jar_status
  end

  -- Directory-tree fallback.
  local plugin_install_dir = plugins_dir .. "/" .. plugin_info.plugin_id
  return install_via_dir(plugin_path, plugin_info, plugin_install_dir)
end

-- Extract and install plugin from Nix store path
function M.install_from_nix_store(plugin_info, nix_store_path, tool_name)
  -- JetBrains plugins in Nix should be in the store path directly or in a lib subdirectory
  local plugin_path = nil

  -- Check different possible locations for the plugin
  local possible_paths = {
    nix_store_path,
    nix_store_path .. "/lib",
    nix_store_path .. "/share",
    nix_store_path .. "/plugins"
  }

  for _, path in ipairs(possible_paths) do
    if shell.path_exists(path, "d") then
      -- `find | head -1` always exits 0, so the first return value of try_exec
      -- (the pcall success boolean) would be true even when the directory holds
      -- zero .jar files. We must inspect the command's stdout to decide.
      local _, find_out = shell.try_exec("find " .. shell.shquote(path) .. ' -name "*.jar" | head -1')
      local has_jar = type(find_out) == "string" and find_out:match("%S") ~= nil
      local has_plugin_xml = shell.path_exists(path .. "/META-INF/plugin.xml", "f")

      if has_jar or has_plugin_xml then
        plugin_path = path
        break
      end
    end
  end

  if not plugin_path then
    error("Could not find plugin files for " .. plugin_info.plugin_id .. " in " .. nix_store_path)
  end

  logger.debug("Plugin path: " .. plugin_path)

  -- Install the plugin
  local install_ok, install_status = M.install_plugin(plugin_path, plugin_info)

  return install_ok, install_status
end

-- Complete JetBrains plugin installation
function M.install_plugin_from_store(nix_store_path, tool_name)
  logger.find("Detected JetBrains plugin: " .. tool_name)

  -- Extract plugin information from tool name
  local plugin_info = M.extract_plugin_info(tool_name)
  if not plugin_info then
    error("Could not extract plugin information from: " .. tool_name)
  end

  logger.debug("Plugin info - IDE: " .. plugin_info.ide .. ", Version: " .. plugin_info.version .. ", Plugin ID: " .. plugin_info.plugin_id)

  -- Install plugin from Nix store
  local install_ok, install_status = M.install_from_nix_store(plugin_info, nix_store_path, tool_name)

  if not install_ok then
    error("JetBrains plugin installation failed for " .. tool_name)
  end

  -- Handle CI skip case
  if install_status == "skipped_in_ci" then
    logger.pack("JetBrains plugin prepared (installation skipped in CI): " .. plugin_info.plugin_id)
  else
    logger.pack("JetBrains plugin installed: " .. plugin_info.plugin_id)
  end

  return plugin_info.plugin_id
end

return M