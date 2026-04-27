-- SPDX-License-Identifier: Apache-2.0
-- Copyright (c) 2024 Jose Badeau (https://github.com/jbadeau/mise-nix)
-- Modifications: Copyright (c) 2026 Ghislain LE MEUR

-- Security functions for local flake handling and validation
local shell = require("shell")

local M = {}

-- Check if local flakes are allowed via environment variable
function M.allow_local_flakes()
  return os.getenv("MISE_NIX_ALLOW_LOCAL_FLAKES") == "true"
end

-- Validate that a local path is safe to use.
-- Policy: resolve the path against cwd, then require it to be a strict
-- descendant of cwd. Any unresolved `..` segment (as a path component) is
-- rejected outright -- previous logic allowed up to two `..` segments,
-- which let paths like `../../etc/passwd` through.
function M.is_safe_local_path(path)
  if not path or type(path) ~= "string" or path == "" then return false end

  -- Reject any `..` that appears as a path component (whether at the start,
  -- middle, or end). This is stricter than the old `up_count > 2` heuristic.
  if path == ".." or path:match("^%.%./") or path:match("/%.%./") or path:match("/%.%.$") then
    return false
  end

  -- Block obviously dangerous absolute paths. The per-user dotfile list
  -- targets directories whose contents are credentials or secret material:
  --   .ssh   — private keys, known_hosts (host pivot)
  --   .gnupg — GPG keyrings, agent socket
  --   .aws   — AWS credentials / config (sts tokens)
  --   .docker — auth.json (registry creds), config.json (proxies)
  --   .kube  — kubeconfig (cluster admin tokens, client certs)
  -- Adding a directory here is a defence-in-depth move; the cwd-descendant
  -- check below is what actually contains a malicious flake, but a flake
  -- that *escaped* cwd should still not be allowed to reference these.
  local dangerous_patterns = {
    "^/etc/", "^/usr/", "^/bin/", "^/sbin/", "^/boot/", "^/root/",
    "^/home/[^/]+/%.ssh/",
    "^/home/[^/]+/%.gnupg/",
    "^/home/[^/]+/%.aws/",
    "^/home/[^/]+/%.docker/",
    "^/home/[^/]+/%.kube/",
  }
  for _, pattern in ipairs(dangerous_patterns) do
    if path:match(pattern) then return false end
  end

  -- Resolve path against cwd and require the result to live inside cwd.
  -- shell.exec can return nil when the subprocess fails to spawn (PATH
  -- scrubbed, TMPDIR unwritable, etc.). Chaining :gsub on nil would crash
  -- with "attempt to index a nil value" — coerce to "" first and bail.
  local cwd = (shell.exec("pwd 2>/dev/null") or ""):gsub("%s+$", "")
  if cwd == "" then return false end

  local realpath = (shell.exec("realpath -m " .. shell.shquote(path) .. " 2>/dev/null || echo INVALID") or "")
                    :gsub("%s+$", "")
  if realpath == "" or realpath == "INVALID" then return false end

  -- Strict descendant check: either equal to cwd or start with cwd + "/".
  return realpath == cwd or realpath:sub(1, #cwd + 1) == (cwd .. "/")
end

-- Validate local flake security before building.
-- Takes an already-parsed flake descriptor (as produced by flake.parse_reference)
-- rather than re-parsing -- this breaks the former flake <-> security require
-- cycle: security no longer needs to require("flake").
function M.validate_local_flake(parsed)
  local is_local = parsed.url:match("^%.") or parsed.url:match("^/") or
                   parsed.url:match("^path:") or parsed.url:match("^file:")

  if not is_local then return true end

  -- Check if local flakes are allowed
  if not M.allow_local_flakes() then
    error("Local flakes are disabled for security. Set MISE_NIX_ALLOW_LOCAL_FLAKES=true to enable.")
  end

  -- Extract path from URL
  local path = parsed.url
  if path:match("^path:") then
    path = path:gsub("^path:", "")
  elseif path:match("^file:") then
    path = path:gsub("^file:", "")
  end

  -- Validate the path is safe
  if not M.is_safe_local_path(path) then
    error("Local flake path is not safe: " .. path .. ". Path must be within current working directory and not access sensitive system directories.")
  end

  -- Print security warning
  print("⚠️  WARNING: Using local flake - ensure you trust the source: " .. parsed.url)
  print("   Local flakes can execute arbitrary code during evaluation and build.")

  return true
end

return M