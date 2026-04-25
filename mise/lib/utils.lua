-- SPDX-License-Identifier: MIT
-- Copyright (c) 2024 Josh Bode (https://github.com/mise-plugins/mise-nix)

---@type Json
local json = require("json")

---@type Strings
local strings = require("strings")

---@type Cmd
local cmd = require("cmd")

---@type File
local file = require("file")

---@type Log
local log = require("log")

---Get current working directory
---@return string?
local function get_cwd()
  local ok, result = pcall(cmd.exec, "pwd")
  if ok and result then
    return strings.trim_space(result)
  end
  return nil
end

---Find project root
---@param filename string Project filename (e.g. flake.nix)
---@param cwd string? Initial directory to search
---@return string?
local function find_project_root(filename, cwd)
  if cwd == nil then
    cwd = get_cwd()
    if cwd == nil then
      return nil
    end
  end

  ---@cast cwd string

  if file.exists(file.join_path(cwd, filename)) then
    return cwd
  else
    if cwd == "/" then
      return nil
    end
    local parts = strings.split(cwd, "/") ---@type string[]
    table.remove(parts, #parts)
    local parent = strings.join(parts, "/") ---@type string
    if parent == "" then
      parent = "/"
    end
    return find_project_root(filename, parent)
  end
end

---Load environment from command output
---@param command string
---@return DevEnv?
local function get_env(command)
  local ok, result = pcall(cmd.exec, command)
  if ok and result then
    local status, data = pcall(json.decode, result)
    if status and type(data) == "table" then
      return data
    end
  end

  return nil
end

---Check whether `path` is tracked by git inside `root`.
---Returns `true` if tracked OR if `root` is not a git working tree (so
---non-git users are not flagged). Returns `false` only when we positively
---confirm that `path` exists in a git repo but isn't tracked -- the case
---where Nix silently ignores the file and produces the opaque
---"Failed to load environment" error downstream.
---
---Two subtleties worth calling out:
---  1. `cd %q && ...; echo <marker>` pattern -- mise's native cmd.exec
---     swallows non-zero exit codes and always returns stdout, so we
---     cannot rely on pcall() to signal git failures. Parse the marker
---     instead.
---  2. `git` in the container PATH may be a mise shim
---     (`/opt/mise/data/shims/git`) that re-invokes mise, which in turn
---     re-runs every [env] hook -- including this one -- causing an
---     infinite shim cascade. We break the cycle by:
---       (a) short-circuiting via file.exists(".git") when the directory
---           isn't a git repo (no need to invoke git at all), and
---       (b) exporting MISE_NIX_HOOK_REENTRY=1 in the git subprocess so
---           the recursively-entered load_env() bails out early.
---@param root string
---@param path string
---@return boolean
local function is_git_tracked(root, path)
  -- No .git directory → either a bare non-repo or a detached worktree.
  -- Treat as "tracked" so non-git users are not warned.
  if not file.exists(file.join_path(root, ".git")) then
    return true
  end
  -- `export` (not `VAR=1 cmd`) so MISE_NIX_HOOK_REENTRY survives past the
  -- first command. The VAR=value prefix syntax only sets the variable for
  -- the immediately-following simple command (here `cd`), NOT for commands
  -- chained with `&&`. Without export, the `git` subprocess doesn't inherit
  -- the guard and triggers the shim-recursion we are trying to prevent.
  local ok, result = pcall(cmd.exec, string.format(
    "export MISE_NIX_HOOK_REENTRY=1; cd %q && " ..
    "if git ls-files --error-unmatch -- %q >/dev/null 2>&1; then " ..
    "  echo tracked; else echo untracked; fi",
    root, path))
  if not ok or type(result) ~= "string" then
    return true  -- conservative: don't warn if we can't decide
  end
  if result:find("untracked") then return false end
  return true
end

---Get environment info.
---
---Returns (result, errors): `result` is the devenv table on success, nil on
---failure; `errors` is a list of diagnostic strings to surface to the user
---(or nil if nothing to show). Callers MUST decide whether to log -- we
---don't call log.error ourselves because mise executes MiseEnv and
---MisePath in separate Lua processes, so module-level dedupe flags don't
---work. Instead, mise_env.lua logs the errors and mise_path.lua discards
---them, giving users exactly one copy of each diagnostic per `mise env`
---invocation.
---@param options Options
---@return {env: DevEnv, lock_file: string}?, string[]?
local function load_env(options)
  -- Break the mise-shim recursion: is_git_tracked() exports
  -- MISE_NIX_HOOK_REENTRY=1 before exec'ing git. When git is a mise shim,
  -- it re-invokes mise which would re-run [env] hooks (including ours) and
  -- spawn an infinite cascade. Bail out silently on reentry -- returning
  -- nil here makes the outer hook return an empty env, which is what the
  -- shim caller expects anyway (it only needs to resolve `git`).
  if os.getenv("MISE_NIX_HOOK_REENTRY") == "1" then
    return nil
  end

  if options.flake_attr == nil then
    options.flake_attr = "default"
  end
  if options.flake_lock == nil then
    options.flake_lock = "flake.lock"
  end
  if options.profile_dir == nil then
    options.profile_dir = ".mise-nix"
  end

  local project_root = find_project_root("flake.nix")
  if project_root == nil then
    log.error("Unable to find flake")
    return nil
  end

  local lock_file = file.join_path(project_root, options.flake_lock)
  local profile_dir = file.join_path(project_root, options.profile_dir)

  if not file.exists(lock_file) then
    log.error("Lock file does not exist:", lock_file)
    return nil
  end

  -- Nix flakes ignore untracked files in a git working tree by design
  -- (reproducibility guarantee). Without this check the user hits an
  -- opaque "Failed to load environment" when they forgot to `git add`
  -- the flake — the most common first-run trip-up for this plugin.
  -- MISE_NIX_ALLOW_UNTRACKED=1 is a user-facing opt-out of the
  -- git-tracked requirement. When set, we skip the is_git_tracked check
  -- AND switch the flake ref from "." (git+file fetcher, enforces tracked
  -- files) to "path:." (path fetcher, reads whatever is physically in
  -- the directory). Intended for throwaway flakes or local-only dev
  -- scenarios where the user genuinely doesn't want the file in git --
  -- not even as intent-to-add. Default stays strict because untracked
  -- flakes silently drift and break reproducibility.
  local allow_untracked = os.getenv("MISE_NIX_ALLOW_UNTRACKED") == "1"

  if not allow_untracked and not is_git_tracked(project_root, "flake.nix") then
    -- -f in the hint forces intent-to-add even when flake.nix / flake.lock
    -- are listed in .gitignore (a common setup — the user wants Nix to see
    -- them without committing their content). The alternative is to set
    -- MISE_NIX_ALLOW_UNTRACKED=1, documented on the third line below.
    return nil, {
      "flake.nix exists at " .. project_root .. " but is not tracked by git.",
      "Nix ignores untracked files in git working trees (reproducibility).",
      "Fix: git -C " .. project_root .. " add -fN flake.nix flake.lock",
      "Or bypass: MISE_NIX_ALLOW_UNTRACKED=1 (reads flake.nix via the path: fetcher)",
    }
  end

  -- Capture nix's stderr in a temp file so that when print-dev-env fails
  -- we can surface the real diagnostic instead of the generic
  -- "Failed to load environment".
  local stderr_file = os.tmpname()

  -- "path:.#attr" forces the path fetcher (no git filtering).
  -- ".#attr"     uses git+file when the directory is a git repo.
  local flake_ref = (allow_untracked and "path:." or ".") .. "#" .. options.flake_attr

  ---@type DevEnv?
  local env = get_env(([=[
    set -eu

    PROFILE_DIR=%q
    LOCK_FILE=%q
    FLAKE_REF=%q
    STDERR=%q

    mkdir -p "${PROFILE_DIR}"
    echo "*" > "${PROFILE_DIR}/.gitignore"

    nix profile wipe-history \
      --quiet \
      --profile "${PROFILE_DIR}/profile" 2>>"${STDERR}"

    nix print-dev-env "${FLAKE_REF}" \
      --quiet \
      --profile "${PROFILE_DIR}/profile" \
      --reference-lock-file "${LOCK_FILE}" \
      --option warn-dirty false \
      --json 2>>"${STDERR}"
  ]=]):format(profile_dir, lock_file, flake_ref, stderr_file))

  if env == nil then
    local f = io.open(stderr_file, "r")
    local stderr = f and f:read("*a") or ""
    if f then f:close() end
    os.remove(stderr_file)

    local errs = { "Failed to load environment" }
    for line in stderr:gmatch("[^\n]+") do
      table.insert(errs, line)
    end
    return nil, errs
  end

  os.remove(stderr_file)
  return { env = env, lock_file = lock_file }, nil
end

return {
  find_project_root = find_project_root,
  load_env = load_env,
}
