-- SPDX-License-Identifier: Apache-2.0
-- Copyright (c) 2024 Jose Badeau (https://github.com/jbadeau/mise-nix)
-- Modifications: Copyright (c) 2026 Ghislain LE MEUR

-- Nixhub.io API integration for package metadata
local http = require("http")
local json = require("json")
local shell = require("shell")

local M = {}

-- Get the base URL for nixhub API
function M.get_base_url()
  return os.getenv("MISE_NIX_NIXHUB_BASE_URL") or "https://search.devbox.sh"
end

-- Cache config
-- A file-level cache of nixhub responses lets `mise hook-env --reason chpwd`
-- avoid hitting the network every time a "latest"-pinned nix:pkg is in the
-- config. Without this, each directory change triggers one HTTP call per
-- nix:* tool, adding 5+ seconds of latency on slow networks.
local function cache_dir()
  local home = os.getenv("HOME") or "/tmp"
  return (os.getenv("MISE_NIX_NIXHUB_CACHE_DIR") or (home .. "/.cache/mise-nix/nixhub"))
end

local function cache_ttl()
  return tonumber(os.getenv("MISE_NIX_NIXHUB_CACHE_TTL") or "86400") -- 24h default
end

local function cache_path(tool)
  local safe = tool:gsub("[^%w._+@-]", "_")
  return cache_dir() .. "/" .. safe .. ".json"
end

local function file_exists(path)
  local f = io.open(path, "r")
  if f then f:close(); return true end
  return false
end

local function file_mtime(path)
  -- `stat -c %Y` is GNU (Linux), `stat -f %m` is BSD (macOS). Try GNU first,
  -- fall back to BSD so the cache TTL logic keeps working on Darwin hosts.
  -- shell.shquote() replaces the previous ad-hoc gsub escape for consistency
  -- with the rest of the plugin.
  local q = shell.shquote(path)
  local fh = io.popen("stat -c %Y " .. q .. " 2>/dev/null || stat -f %m " .. q .. " 2>/dev/null")
  if not fh then return nil end
  local out = fh:read("*l")
  fh:close()
  return tonumber(out)
end

local function read_cache(path)
  if not file_exists(path) then return nil end
  local mtime = file_mtime(path)
  if not mtime then return nil end
  if (os.time() - mtime) >= cache_ttl() then return nil end
  local fh = io.open(path, "r")
  if not fh then return nil end
  local body = fh:read("*a")
  fh:close()
  if not body or body == "" then return nil end
  local ok, data = pcall(json.decode, body)
  if not ok or type(data) ~= "table" then return nil end
  return data, body
end

local function write_cache(path, body)
  os.execute("mkdir -p " .. shell.shquote(cache_dir()))
  local fh = io.open(path, "w")
  if not fh then return end
  fh:write(body)
  fh:close()
end

-- Fetch tool metadata from nixhub.io (with file cache)
function M.fetch_metadata(tool)
  local cp = cache_path(tool)

  -- Cache hit within TTL → return without network
  local cached, cached_body = read_cache(cp)
  if cached then
    return true, cached, cached_body
  end

  local url = M.get_base_url() .. "/v2/pkg?name=" .. tool

  -- Use native HTTP module
  local resp, err = http.get({
    url = url,
    headers = {
      ['User-Agent'] = 'mise-nix'
    }
  })

  if err ~= nil then
    return false, nil, "HTTP request failed: " .. err
  end

  if resp.status_code ~= 200 then
    return false, nil, "HTTP error: " .. resp.status_code
  end

  if not resp.body or resp.body == "" then
    return false, nil, "Empty response from nixhub.io"
  end

  local success, data = pcall(json.decode, resp.body)
  if success then
    write_cache(cp, resp.body)
  end
  return success, data, resp.body
end

-- Validate that metadata fetch was successful and contains expected data
function M.validate_metadata(success, data, tool, response)
  if not success or type(data) ~= "table" or type(data.releases) ~= "table" then
    -- Create a more user-friendly error message
    local error_msg = "Package not found: " .. tool .. " at https://nixhub.io. Search for available packages at https://search.nixos.org/packages"
    
    -- Only include response details if they're meaningful
    if response and response:match("^{") then
      -- It's JSON, try to extract just the message
      local message = response:match('"message":"([^"]+)"')
      if message and message ~= "Unexpected Server Error" then
        error_msg = "Package not found: " .. tool .. " (" .. message .. ") at https://nixhub.io. Search for available packages at https://search.nixos.org/packages"
      end
    elseif response and #response > 0 and #response < 200 then
      -- Short, potentially useful response
      error_msg = "Package not found: " .. tool .. " (" .. response .. ") at https://nixhub.io. Search for available packages at https://search.nixos.org/packages"
    end
    
    error(error_msg)
  end
end

return M