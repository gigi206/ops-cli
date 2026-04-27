-- SPDX-License-Identifier: Apache-2.0
-- Copyright (c) 2024 Jose Badeau (https://github.com/jbadeau/mise-nix)

-- Nix flake reference handling and manipulation
local shell = require("shell")
local logger = require("logger")
local platform = require("platform")

local M = {}

-- Detect if a tool name is a flake reference
function M.is_reference(tool)
  if not tool or type(tool) ~= "string" then return false end

  -- Check for flake reference patterns (including custom prefixes)
  local patterns = {
    -- Standard Nix flake patterns
    "^github:",           -- github:owner/repo#package (standard Nix GitHub flake)
    "^gitlab:",           -- gitlab:group/project#package (standard Nix GitLab flake)
    "^git%+https://",     -- git+https://...#package (standard Nix git flake)
    "^git%+ssh://",       -- git+ssh://...#package (standard Nix git flake)
    "^path:",             -- path:/some/path#package (path URI)
    "^file:",             -- file:/some/path#package (file URI)
    "nixpkgs#",           -- nixpkgs#hello (nixpkgs shorthand)
    
    -- Local path patterns (must contain # to be flake reference)
    "^%./.*#",            -- ./my-flake#package (relative path)
    "^%../.*#",           -- ../my-flake#package (relative path)
    "^/.*#",              -- /absolute/path/flake#tool (absolute path with # for flake)
    
    -- Owner/repo shorthand (e.g., nixos/nixpkgs#hello)
    "^[%w%-_%.]+/[%w%-_%.]+#", -- owner/repo#package shorthand
    
    -- Custom patterns with plus separator
    "^github%+",          -- github+owner/repo#package (GitHub shorthand)
    "^gitlab%+",          -- gitlab+group/project#package (GitLab shorthand)
    "^vscode%+install=vscode%-extensions%.", -- vscode+install=vscode-extensions.publisher.extension (VSCode extension install)
    "^ssh%+",             -- ssh+host/repo.git#package (for tool@source only)
    "^https%+",           -- https+host/repo.git#package (for tool@source only)
    "^vscode%-extensions%.", -- vscode-extensions.publisher.extension (normal package)
  }

  for _, pattern in ipairs(patterns) do
    if tool:match(pattern) then return true end
  end

  -- Intentionally ambiguous: bare `name#attr` (no `./` prefix, no scheme)
  -- could be either a relative path flake OR a regular package with `#`
  -- in its name. We treat it as NOT a flake reference; users who really
  -- mean a local flake must spell it `./name#attr` (matched by the
  -- "^%./.*#" pattern above).
  return false
end

-- Convert custom git prefixes to standard nix flake URLs
function M.convert_custom_git_prefix(version)
  if not version or type(version) ~= "string" then return version end
  
  -- SSH URLs: ssh+... -> git+ssh://...
  if version:match("^ssh%+") then
    local path = version:gsub("^ssh%+", "")
    -- Ensure proper URL format for git+ssh
    if not path:match("^[%w%-_%.]+@") then
      -- If it doesn't start with user@, add git@ prefix
      path = "git@" .. path
    end
    return "git+ssh://" .. path
  end
  
  -- HTTPS URLs: https+... -> git+https://...
  if version:match("^https%+") then
    local path = version:gsub("^https%+", "")
    return "git+https://" .. path
  end
  
  -- GitHub shorthand: github+user/repo -> github:user/repo
  -- Supports nested paths like github+owner/repo/subdir
  if version:match("^github%+") then
    local path = version:gsub("^github%+", "")
    return "github:" .. path
  end

  -- GitLab shorthand: gitlab+group/project -> gitlab:group/project
  -- Supports nested groups like gitlab+group/subgroup/project
  if version:match("^gitlab%+") then
    local path = version:gsub("^gitlab%+", "")
    return "gitlab:" .. path
  end

  return version
end

-- Parse flake reference into components with enhanced ref support
function M.parse_reference(flake_ref)
  -- Handle VSCode install syntax (vscode+install=vscode-extensions.publisher.extension)
  if flake_ref:match("^vscode%+install=vscode%-extensions%.") then
    local ext_package = flake_ref:gsub("^vscode%+install=", "")
    return {
      url = "nixpkgs",
      attribute = ext_package,
      full_ref = "nixpkgs#" .. ext_package,
      install_mode = "vscode"
    }
  end
  
  -- Handle VSCode extensions directly (vscode-extensions.publisher.extension)
  if flake_ref:match("^vscode%-extensions%.") then
    return {
      url = "nixpkgs",
      attribute = flake_ref,
      full_ref = "nixpkgs#" .. flake_ref
    }
  end
  
  local flake_url, attribute = flake_ref:match("^(.-)#(.+)$")

  -- If no attribute is explicitly provided, assume 'default'
  if not attribute and flake_ref:find("#") then
      error("Invalid flake reference format. Expected 'flake_url#attribute', but attribute is empty after '#'. Got: " .. flake_ref)
  elseif not attribute then -- No '#' found, so attribute is implicitly 'default'
      flake_url = flake_ref
      attribute = "default"
  end

  -- Convert custom git prefixes to standard nix flake URLs
  flake_url = M.convert_custom_git_prefix(flake_url)

  -- Note: Nix natively supports all standard flake URL formats
  -- (github:owner/repo[/ref], github:owner/repo?ref=X, gitlab:..., …)
  -- so we don't transform those here — they pass through to `nix build`.

  -- Normalize GitHub shorthand (owner/repo -> github:owner/repo)
  -- But exclude local paths that start with ./ or ../
  if flake_url:match("^[%w%-_%.]+/[%w%-_%.]+$") and not flake_url:match("^%.") then
    flake_url = "github:" .. flake_url
  end

  return {
    url = flake_url,
    attribute = attribute,
    full_ref = flake_url .. "#" .. attribute
  }
end

-- Flakes don't expose an enumerable version registry the way classical
-- package indexes do (no equivalent of `pypi.org/pypi/<pkg>/json`). Callers
-- that need to pin a specific revision do it through M.build(flake_ref,
-- version) which appends `/<rev>` or `?rev=…` to the flake URI. This hook
-- therefore returns a single logical slot — "latest" for remote flakes,
-- "local" for local ones — so mise's version selector stays consistent.
function M.get_versions(flake_ref)
  local parsed = M.parse_reference(flake_ref)

  -- Try to get commit info if it's a git-based flake
  if parsed.url:match("github:") or parsed.url:match("gitlab:") or parsed.url:match("git%+") then
    return {"latest"}  -- For now, just return "latest"
  elseif parsed.url:match("^%.") or parsed.url:match("^/") or parsed.url:match("^path:") or parsed.url:match("^file:") then
    -- Local flakes - return current state
    return {"local"}
  else
    return {"latest"} -- Default for other recognized flake types
  end
end

-- Build a flake reference with security validation
function M.build(flake_ref, version)
  local security = require("security")

  -- Validate that it's actually a flake reference. Quote the offending
  -- value so users see what they passed (the previous bare error left
  -- them debugging blind).
  if not M.is_reference(flake_ref) then
    error("Invalid flake reference: " .. tostring(flake_ref) ..
          " (expected one of: github:owner/repo#attr, gitlab:..., git+https://..., path:..., owner/repo#attr)")
  end

  local parsed = M.parse_reference(flake_ref)

  -- Security validation for local flakes (pass already-parsed descriptor to
  -- avoid a flake <-> security require cycle).
  security.validate_local_flake(parsed)

  local build_ref = parsed.full_ref

  -- If version is specified and not "latest"/"local"/"", try to append it as a revision
  if version and version ~= "latest" and version ~= "local" and version ~= "" then
    -- For git-based flakes, we can specify a revision
    if parsed.url:match("github:") or parsed.url:match("gitlab:") then
      -- Remove any existing revision (if present) and add the new one.
      -- Only strip a trailing hex suffix when it looks like a real git
      -- revision (>= 7 hex chars — git's default abbrev length). The
      -- previous `[a-fA-F0-9]+$` accepted ANY hex tail, including a
      -- short subdir name that happened to be hex-only (e.g.
      -- `github:owner/repo/abc` would lose `abc`). Lua patterns lack
      -- `{n,}`, so we capture the suffix and check its length manually.
      local stripped = parsed.url
      local before, hex = stripped:match("^(.-)/(%x+)$")
      if before and hex and #hex >= 7 then
        stripped = before
      end
      local base_url = stripped:gsub("/v?%d+%.%d+%.%d+.*$", "") -- Remove existing semver tag
      build_ref = base_url .. "/" .. version .. "#" .. parsed.attribute
    elseif parsed.url:match("git%+") then
      -- For git+ URLs, we need to add ?ref= or ?rev= parameter
      local separator = parsed.url:find("?") and "&" or "?"
      -- Remove existing ref/rev if present before adding the new one
      -- Note: Lua patterns don't support | alternation, so we do separate replacements
      local cleaned_url = parsed.url:gsub("[%?&]ref=[^&#]+", ""):gsub("[%?&]rev=[^&#]+", ""):gsub("[?&]$", "")
      build_ref = cleaned_url .. separator .. "rev=" .. version .. "#" .. parsed.attribute
    end
  end

  local env_prefix = platform.get_env_prefix()
  local impure_flag = platform.get_impure_flag()
  -- shell.shquote wraps the ref in '…', escaping any embedded single-quote —
  -- safer than the previous hand-written "'%s'" when build_ref ends up with a
  -- literal apostrophe (rare in flake URIs, fatal if it happens).
  local cmdline = string.format("%snix build %s--no-link --print-out-paths %s", env_prefix, impure_flag, shell.shquote(build_ref))

  logger.step("Building flake " .. build_ref .. "...")
  local result = shell.exec(cmdline)
  local outputs = {}
  for path in result:gmatch("[^\n]+") do
    table.insert(outputs, path)
  end

  if #outputs == 0 then
    error("No outputs returned by nix build for flake: " .. build_ref)
  end

  return outputs, build_ref
end

return M