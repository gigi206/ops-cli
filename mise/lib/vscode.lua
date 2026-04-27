-- SPDX-License-Identifier: Apache-2.0
-- Copyright (c) 2024 Jose Badeau (https://github.com/jbadeau/mise-nix)
-- Modifications: Copyright (c) 2026 Ghislain LE MEUR

-- VSCode extension detection, management, and installation
local shell = require("shell")
local logger = require("logger")
local tempdir = require("tempdir")
local cmd = require("cmd")
local file = require("file")
local plugin_matcher = require("plugin_matcher")

local M = {}

-- Escape the five XML predefined entities so values extracted from
-- `package.json` (displayName, description, categories, …) cannot break
-- the manifest XML or inject sibling elements. Order matters: `&` must be
-- replaced first, otherwise the `&amp;` introduced by later substitutions
-- would themselves be re-escaped.
local function xml_escape(s)
  if not s or s == "" then return s or "" end
  s = tostring(s)
  s = s:gsub("&", "&amp;")
  s = s:gsub("<", "&lt;")
  s = s:gsub(">", "&gt;")
  s = s:gsub('"', "&quot;")
  s = s:gsub("'", "&apos;")
  return s
end

-- Extension detection
function M.is_extension(tool_name)
  return plugin_matcher.matches(tool_name,
    "^vscode%-extensions%.",
    "^vscode%+install=vscode%-extensions%.")
end

function M.extract_extension_id(tool_or_flake)
  return plugin_matcher.extract(tool_or_flake,
    "vscode%-extensions%.(.+)",
    "^vscode%+install=vscode%-extensions%.(.+)")
end

-- Directory management
function M.get_extensions_dir()
  return os.getenv("HOME") .. "/.vscode/extensions"
end

-- Removed: Extension symlink installation is no longer used
-- We now only use VSIX installation for proper VSCode integration

-- VSIX installation (for VSCode recognition)
function M.install_via_vsix(vsix_path)
  -- In CI environments, skip actual VSCode installation since it's experimental
  if os.getenv("CI") or os.getenv("GITHUB_ACTIONS") then
    logger.info("Skipping VSCode extension installation in CI environment")
    logger.info("VSCode extension functionality is experimental and not reliable in headless CI")
    return true, "skipped_in_ci"
  end

  -- Try to install the extension locally.
  -- shell.shquote() wraps vsix_path in single quotes and escapes any embedded
  -- apostrophes — the previous literal "…%s…" double-quoted form let a weird
  -- path (unlikely but possible on tmpfs test fixtures) break out of the word.
  local final_cmd = "code --install-extension " .. shell.shquote(vsix_path) .. " 2>&1"

  local ok, output = shell.try_exec(final_cmd)

  -- Ensure output is a string
  local output_str = ""
  if output then
    if type(output) == "string" then
      output_str = output
    else
      output_str = tostring(output)
    end
  end

  -- VSCode might return non-zero exit code even on success, so check output content
  if output_str ~= "" and (output_str:match("successfully installed") or output_str:match("Extension.*installed")) then
    logger.done("VSCode extension installed via VSIX")
    -- Print the success message
    for line in output_str:gmatch("[^\n]+") do
      if line:match("successfully installed") or line:match("Extension.*installed") then
        print("   " .. line)
      end
    end
    return true, "installed"
  elseif output_str ~= "" and output_str:match("is already installed") then
    logger.info("VSCode extension already installed")
    return true, "already_installed"
  else
    -- If we get here, there was likely a real failure
    logger.fail("VSCode VSIX installation failed")
    logger.debug("Command success: " .. tostring(ok))
    logger.debug("Command output: " .. (output_str or "nil"))
    logger.debug("Output type: " .. type(output))
    if output_str ~= "" then
      print("   Error: " .. output_str)
    else
      print("   Error: No error message available")
    end
    return false, output_str
  end
end

-- Create required VSIX manifest files
function M.create_vsix_manifest(temp_dir, ext_id, ext_path)
  -- Read package.json to extract extension metadata.
  -- Use io.open instead of `cat` via try_exec: try_exec's first return value
  -- (the pcall-success boolean) is true even when cat fails, so the previous
  -- code accepted shell error text as if it were package.json content and
  -- silently fell back to placeholder defaults.
  local package_json_path = ext_path .. "/package.json"
  local package_json_content = ""
  do
    local fh = io.open(package_json_path, "r")
    if fh then
      package_json_content = fh:read("*a") or ""
      fh:close()
    end
  end

  -- Simple regex extraction of the fields we need. When package.json is
  -- missing or doesn't contain a key, every :match returns nil and the
  -- `or <default>` fallback applies — covers the "no package.json" case
  -- without an explicit branch (`""` is truthy in Lua so a guarded
  -- `if package_json_content then` would always be taken anyway).
  local package_data = {}
  package_data.name        = package_json_content:match('"name"%s*:%s*"([^"]+)"')        or ext_id
  package_data.displayName = package_json_content:match('"displayName"%s*:%s*"([^"]+)"') or package_data.name
  package_data.description = package_json_content:match('"description"%s*:%s*"([^"]+)"') or ""
  package_data.version     = package_json_content:match('"version"%s*:%s*"([^"]+)"')     or "1.0.0"
  package_data.publisher   = package_json_content:match('"publisher"%s*:%s*"([^"]+)"')   or "unknown"
  package_data.categories  = package_json_content:match('"categories"%s*:%s*%[([^%]]+)%]') or ""
  package_data.keywords    = package_json_content:match('"keywords"%s*:%s*%[([^%]]+)%]')   or ""
  package_data.icon        = package_json_content:match('"icon"%s*:%s*"([^"]+)"')        or ""
  package_data.license     = package_json_content:match('"license"%s*:%s*"([^"]+)"')     or ""

  local engines = package_json_content:match('"engines"%s*:%s*{([^}]+)}')
  package_data.engine = (engines and engines:match('"vscode"%s*:%s*"([^"]+)"')) or "^1.74.0"
  
  -- Create [Content_Types].xml with common file types for VSCode extensions
  local content_types = [[<?xml version="1.0" encoding="utf-8"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension=".json" ContentType="application/json"/><Default Extension=".vsixmanifest" ContentType="text/xml"/><Default Extension=".md" ContentType="text/markdown"/><Default Extension=".js" ContentType="application/javascript"/><Default Extension=".ts" ContentType="application/typescript"/><Default Extension=".html" ContentType="text/html"/><Default Extension=".css" ContentType="text/css"/><Default Extension=".scss" ContentType="text/css"/><Default Extension=".less" ContentType="text/css"/><Default Extension=".xml" ContentType="text/xml"/><Default Extension=".yaml" ContentType="text/yaml"/><Default Extension=".yml" ContentType="text/yaml"/><Default Extension=".txt" ContentType="text/plain"/><Default Extension=".log" ContentType="text/plain"/><Default Extension=".py" ContentType="text/plain"/><Default Extension=".go" ContentType="text/plain"/><Default Extension=".java" ContentType="text/plain"/><Default Extension=".c" ContentType="text/plain"/><Default Extension=".cpp" ContentType="text/plain"/><Default Extension=".h" ContentType="text/plain"/><Default Extension=".hpp" ContentType="text/plain"/><Default Extension=".rs" ContentType="text/plain"/><Default Extension=".php" ContentType="text/plain"/><Default Extension=".rb" ContentType="text/plain"/><Default Extension=".sh" ContentType="text/plain"/><Default Extension=".png" ContentType="image/png"/><Default Extension=".jpg" ContentType="image/jpeg"/><Default Extension=".jpeg" ContentType="image/jpeg"/><Default Extension=".gif" ContentType="image/gif"/><Default Extension=".svg" ContentType="image/svg+xml"/><Default Extension=".ico" ContentType="image/x-icon"/><Default Extension=".ttf" ContentType="font/ttf"/><Default Extension=".woff" ContentType="font/woff"/><Default Extension=".woff2" ContentType="font/woff2"/><Default Extension=".eot" ContentType="application/vnd.ms-fontobject"/></Types>]]
  
  -- Write directly via Lua io so arbitrary content (including a lone "EOF"
  -- line) can't prematurely close a shell heredoc.
  do
    local ct_path = temp_dir .. "/[Content_Types].xml"
    local fh, err = io.open(ct_path, "w")
    if not fh then error("failed to open " .. ct_path .. ": " .. tostring(err)) end
    fh:write(content_types)
    fh:close()
  end
  
  -- Determine icon and license paths
  local icon_path = ""
  local license_path = ""
  
  if package_data.icon ~= "" then
    icon_path = "extension/" .. package_data.icon
  else
    -- Look for common icon files
    local common_icons = {"icon.png", "images/icon.png", "media/icon.png", "assets/icon.png"}
    for _, icon_file in ipairs(common_icons) do
      if shell.path_exists(ext_path .. "/" .. icon_file, "f") then
        icon_path = "extension/" .. icon_file
        break
      end
    end
  end
  
  -- Look for license files
  local common_licenses = {"LICENSE", "LICENSE.txt", "LICENSE.md", "license", "license.txt", "license.md"}
  for _, license_file in ipairs(common_licenses) do
    if shell.path_exists(ext_path .. "/" .. license_file, "f") then
      license_path = "extension/" .. license_file
      break
    end
  end

  -- Clean up categories and keywords (strip JSON quoting + collapse spaces
  -- around commas), then XML-escape so a payload like `"<script>"` in
  -- package.json cannot break the manifest's `<Categories>` element.
  local categories = xml_escape(package_data.categories:gsub('"', ''):gsub('%s*,%s*', ','))
  local tags = xml_escape(package_data.keywords:gsub('"', ''):gsub('%s*,%s*', ','))

  -- Load the manifest template once per call. Resolves the path relative
  -- to this Lua file rather than the cwd so it survives mise's variable
  -- working directories (`mise install` may run from anywhere).
  local function template_path()
    local here = debug.getinfo(1, "S").source:sub(2)  -- strip leading "@"
    local dir = here:match("^(.*)/[^/]+$") or "."
    return dir .. "/templates/extension.vsixmanifest.tpl"
  end

  local tpl
  do
    local fh, err = io.open(template_path(), "r")
    if not fh then error("failed to open VSIX template at " .. template_path() .. ": " .. tostring(err)) end
    tpl = fh:read("*a") or ""
    fh:close()
  end

  -- Create extension.vsixmanifest from the template. The %s slots, in order:
  --  1-5 : Identity Id / Version / Publisher / DisplayName / Description
  --  6-7 : Tags, Categories
  --  8   : Engine version
  --  9-10: optional <License> / <Icon> blocks (or empty string)
  --  11-13: optional README / CHANGELOG / License asset blocks
  -- Every value pulled from `package.json` (id/version/publisher/display
  -- name/description/engine) is xml_escape'd before insertion to neutralise
  -- `<`, `>`, `&`, quotes — a malformed extension can't poison the manifest
  -- and silently break installation.
  local vsix_manifest = string.format(tpl,
    xml_escape(package_data.name),
    xml_escape(package_data.version),
    xml_escape(package_data.publisher),
    xml_escape(package_data.displayName),
    xml_escape(package_data.description),
    tags, categories,
    xml_escape(package_data.engine),
    license_path ~= "" and string.format('\n\t\t\t<License>%s</License>', xml_escape(license_path)) or "",
    icon_path ~= "" and string.format('\n\t\t\t<Icon>%s</Icon>', xml_escape(icon_path)) or "",
    shell.path_exists(ext_path .. "/README.md", "f") and '\n\t\t\t<Asset Type="Microsoft.VisualStudio.Services.Content.Details" Path="extension/README.md" Addressable="true" />' or "",
    shell.path_exists(ext_path .. "/CHANGELOG.md", "f") and '\n\t\t\t<Asset Type="Microsoft.VisualStudio.Services.Content.Changelog" Path="extension/CHANGELOG.md" Addressable="true" />' or "",
    license_path ~= "" and string.format('\n\t\t\t<Asset Type="Microsoft.VisualStudio.Services.Content.License" Path="%s" Addressable="true" />', xml_escape(license_path)) or ""
  )

  -- Inject the icon asset *after* the templated %s slots (it lives inside
  -- <Assets>, so it can't be a slot at the same level). Lua's gsub treats
  -- `%` in the replacement string as a capture reference (`%0`..`%9`); a
  -- literal `%` in icon_path must be doubled to `%%` before passing.
  if icon_path ~= "" then
    local repl = string.format(
      '\t\t\t<Asset Type="Microsoft.VisualStudio.Services.Icons.Default" Path="%s" Addressable="true" />\n\t\t</Assets>',
      xml_escape(icon_path)):gsub("%%", "%%%%")
    vsix_manifest = vsix_manifest:gsub("</Assets>", repl)
  end
  
  do
    local mf_path = temp_dir .. "/extension.vsixmanifest"
    local fh, err = io.open(mf_path, "w")
    if not fh then error("failed to open " .. mf_path .. ": " .. tostring(err)) end
    fh:write(vsix_manifest)
    fh:close()
  end
end

-- VSIX file creation and installation in temporary directory only
function M.create_and_install_vsix(ext_id, nix_store_path, tool_name)
  -- VSCode extensions in Nix are located at share/vscode/extensions/{ext_id}
  -- The directory name might have different casing than the extension ID
  local ext_path = nil

  -- First try the exact extension ID
  local test_path = nix_store_path .. "/share/vscode/extensions/" .. ext_id
  if shell.path_exists(test_path, "d") then
    ext_path = test_path
  else
    -- Try to find the actual directory name (case-insensitive).
    -- ext_id is injected into `-iname` where find treats it as a glob, not a
    -- shell command — shquoting the full argument keeps shell metacharacters
    -- harmless.
    local ext_root = nix_store_path .. "/share/vscode/extensions"
    local ok, find_result = shell.try_exec(
      "find " .. shell.shquote(ext_root) ..
      " -maxdepth 1 -type d -iname " .. shell.shquote(ext_id) .. " 2>/dev/null | head -1")
    if ok and find_result and type(find_result) == "string" and find_result ~= "" then
      ext_path = find_result:gsub("%s+$", "") -- trim whitespace
    else
      -- Last resort: get the first (and likely only) extension directory
      ok, find_result = shell.try_exec(
        "find " .. shell.shquote(ext_root) ..
        " -maxdepth 1 -type d ! -path " .. shell.shquote(ext_root) ..
        " 2>/dev/null | head -1")
      if ok and find_result and type(find_result) == "string" and find_result ~= "" then
        ext_path = find_result:gsub("%s+$", "")
        logger.debug("Using found extension directory: " .. ext_path)
      end
    end
  end

  if not ext_path then
    error("Could not find extension directory for " .. ext_id .. " in " .. nix_store_path)
  end

  local vsix_name = (tool_name or ext_id):gsub("%.", "-") .. ".vsix"

  -- Debug-only diagnostics: gate the whole block on is_debug() so the
  -- shell sub-processes aren't spawned in non-debug runs (each was a
  -- noticeable hit on cold installs because cmd.exec forks a sub-shell).
  if logger.is_debug() then
    logger.debug("Extension path: " .. ext_path)
    local ls_result = shell.try_exec("ls -la " .. shell.shquote(ext_path) .. " 2>&1")
    if ls_result then
      logger.debug("Extension directory contents: " .. tostring(ls_result))
    end
    local pkg_check = shell.try_exec("test -f " .. shell.shquote(ext_path .. "/package.json")
      .. ' && echo "package.json found at root" || echo "package.json NOT at root"')
    logger.debug("Package.json check: " .. tostring(pkg_check))
  end

  -- Create VSIX file with proper structure using temporary directory.
  -- Capture install_ok / install_status in the outer scope: pcall wrapping a
  -- function that returns multiple values collapses them on a 2-var
  -- destructure, and with_temp_dir now removes the directory on return so
  -- the VSIX file no longer exists past this block anyway.
  local vsix_path = nil
  local install_ok, install_status = nil, nil
  local zip_ok, zip_result = pcall(function()
    tempdir.with_temp_dir("mise_vsix_" .. ext_id:gsub("%.", "_"), function(temp_dir)
      -- Set the VSIX path within the temp directory
      vsix_path = temp_dir .. "/" .. vsix_name

      cmd.exec("mkdir -p " .. shell.shquote(file.join_path(temp_dir, "extension")))
      -- Copy extension files, handling different possible structures.
      -- The `/.` suffix on the source forces cp to copy *contents* including
      -- dotfiles (.vscodeignore, .vscode/, .gitignore — extensions ship them).
      -- A trailing `/*` glob would expand without dotglob and silently drop them.
      local copy_success = pcall(function()
        shell.exec("cp -r " .. shell.shquote(ext_path) .. "/. " .. shell.shquote(temp_dir) .. "/extension/")
      end)

      if not copy_success then
        -- Fallback: copy the directory itself, then move its contents (incl. dotfiles).
        copy_success = pcall(function()
          shell.exec("cp -r " .. shell.shquote(ext_path) .. " " .. shell.shquote(temp_dir) .. "/extension_tmp"
            .. " && cp -r " .. shell.shquote(temp_dir) .. "/extension_tmp/. " .. shell.shquote(temp_dir) .. "/extension/"
            .. " && rm -rf " .. shell.shquote(temp_dir) .. "/extension_tmp")
        end)
      end
      if not copy_success then
        error("failed to copy extension files from " .. ext_path)
      end
      -- Sanity-check: without package.json the resulting VSIX would be
      -- invalid, so fail loudly rather than producing a silently broken
      -- artifact further down.
      if not shell.path_exists(temp_dir .. "/extension/package.json", "f") then
        error("extension copy produced no package.json in " .. temp_dir .. "/extension")
      end
      -- Fix permissions on copied files so they can be deleted
      shell.exec("chmod -R u+w " .. shell.shquote(temp_dir))

      -- Debug-only: same rationale as above (don't fork sub-shells when
      -- the operator hasn't asked for the extra noise).
      if logger.is_debug() then
        local temp_contents = shell.try_exec("ls -la " .. shell.shquote(temp_dir .. "/extension/") .. " 2>&1 | head -5")
        logger.debug("Temp extension directory contents: " .. tostring(temp_contents))
        local pkg_in_temp = shell.try_exec("test -f " .. shell.shquote(temp_dir .. "/extension/package.json")
          .. ' && echo "package.json exists in temp" || echo "package.json MISSING in temp"')
        logger.debug("Package.json in temp: " .. tostring(pkg_in_temp))
      end

      -- Create required VSIX manifest files
      M.create_vsix_manifest(temp_dir, ext_id, ext_path)

      shell.exec("cd " .. shell.shquote(temp_dir) .. " && zip -r " .. shell.shquote(vsix_name) .. ' . -x "*.DS_Store"')

      logger.done("Created VSIX: " .. vsix_path)

      -- Install the VSIX file directly from temp directory.
      -- Results are assigned to the outer locals above so they survive
      -- tempdir cleanup + the enclosing pcall.
      install_ok, install_status = M.install_via_vsix(vsix_path)
    end)
  end)

  if not zip_ok then
    local error_msg = "unknown error"
    if zip_result then
      if type(zip_result) == "string" then
        error_msg = zip_result
      else
        error_msg = tostring(zip_result)
      end
    end
    logger.fail("VSIX creation failed: " .. error_msg)
    return false, nil
  end

  return install_ok, vsix_path, install_status
end

-- Complete VSCode extension installation (VSIX only - no symlinks or shims)
function M.install_extension(nix_store_path, tool_name)
  logger.find("Detected VSCode extension: " .. tool_name)

  -- Extract extension ID from tool name
  local ext_id = M.extract_extension_id(tool_name)
  if not ext_id then
    error("Could not extract extension ID from: " .. tool_name)
  end

  -- Create VSIX in temp directory and install it in VSCode
  local vsix_ok, vsix_path, install_status = M.create_and_install_vsix(ext_id, nix_store_path, tool_name)

  if not vsix_ok then
    error("VSIX installation failed for " .. tool_name)
  end

  -- Handle CI skip case
  if install_status == "skipped_in_ci" then
    logger.pack("VSCode extension prepared (installation skipped in CI): " .. ext_id)
  else
    logger.pack("VSCode extension installed via VSIX: " .. ext_id)
  end

  return ext_id
end

return M