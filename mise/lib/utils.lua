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

local shell = require("shell")
local tempdir = require("tempdir")

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

---Compute a deterministic cache key for `nix print-dev-env` output.
---
---The key changes whenever any input that affects the resolved devenv
---changes:
---  - flake.lock            -- pins every external input
---  - every *.nix file       -- catches local imports (`import ./shell.nix`)
---                             that flake.lock alone cannot pin
---  - flake_ref              -- "." (git+file) vs "path:." (path fetcher)
---  - flake_attr             -- which devShell attribute to read
---  - uname -m               -- the resolved nix store paths are arch-specific
---
---Returns a 16-char lowercase hex string, or nil if hashing failed (in which
---case load_env() falls back to the slow path -- caching is best-effort).
---@param project_root string
---@param flake_ref string
---@param flake_attr string
---@return string?
local function compute_cache_key(project_root, flake_ref, flake_attr)
  -- find ... -prune skips .git/ and .mise-nix/ (which contains the cache
  -- itself + the nix profile symlink — both would create a feedback loop).
  -- xargs -0 cat is bounded by find output size; for typical flakes this is
  -- a handful of small files (< 100 KB total).
  local cmd_str = ([=[
    set -eu
    cd %s
    {
      cat flake.lock 2>/dev/null || true
      find . \( -path ./.git -o -path ./.mise-nix \) -prune -o \
        -name '*.nix' -type f -print0 \
        | sort -z | xargs -0 cat 2>/dev/null
      printf '%%s\n' %s
      printf '%%s\n' %s
      uname -m
    } | sha256sum | cut -c1-16
  ]=]):format(shell.shquote(project_root),
              shell.shquote(flake_ref),
              shell.shquote(flake_attr))

  local ok, out = pcall(cmd.exec, cmd_str)
  if not ok or type(out) ~= "string" then return nil end
  local key = strings.trim_space(out)
  -- Sanity-check: sha256sum + cut should yield 16 hex chars. If anything
  -- unexpected slipped through (binary in stdout, locale issue, etc.), bail
  -- to the slow path rather than build a malformed cache filename.
  if not key:match("^[0-9a-f]+$") or #key ~= 16 then return nil end
  return key
end

---Load a cached devenv table from disk. Returns nil on any miss/error.
---
---Also invalidates the cache when the nix store has been garbage-collected
---out from under it: the profile symlink (`<profile_dir>/profile`) is a
---gc-root pointing into /nix/store, so if its target is missing every
---store path the JSON references is also gone. Trusting the cache in that
---state would expose a PATH full of broken /nix/store/* segments and make
---the user's binaries silently unavailable.
---@param cache_file string
---@param profile_dir string
---@return table?
local function load_from_cache(cache_file, profile_dir)
  if not file.exists(cache_file) then return nil end

  -- `test -e` follows symlinks, so a profile symlink whose target was
  -- gc-collected reports non-existent. shell.path_exists wraps cmd.exec
  -- in pcall and parses a marker word -- a raw `cmd.exec("test -e ...")`
  -- raises on non-zero exit, which would propagate up through MiseEnv
  -- and crash the hook (mise prints a Lua traceback and bails out).
  local profile_link = file.join_path(profile_dir, "profile")
  if not shell.path_exists(profile_link, "e") then return nil end

  local f = io.open(cache_file, "r")
  if not f then return nil end
  local content = f:read("*a")
  f:close()
  if not content or content == "" then return nil end
  local ok, data = pcall(json.decode, content)
  if not ok or type(data) ~= "table" then return nil end
  return data
end

---Persist a devenv table to the cache atomically.
---
---Concurrency model: mise runs MiseEnv and MisePath in separate Lua
---processes. On a cold cache they both call load_env(), both miss, both
---exec `nix print-dev-env`, and both write the cache. mv(2) (rename) is
---atomic on POSIX -- the worst case is the slower writer overwriting the
---faster one with byte-identical content (writes are deterministic for a
---given cache key, so there is no semantic divergence). No flock needed.
---@param cache_file string
---@param env table
local function save_to_cache(cache_file, env)
  local ok, payload = pcall(json.encode, env)
  if not ok or type(payload) ~= "string" then return end
  -- Tmp filename includes time + 7-digit random so two parallel writers
  -- never collide on the staging path. mktemp(1) would be safer (atomic
  -- O_EXCL) but cmd.exec's stdout-only contract makes it awkward to read
  -- the path back; the predictable name is fine for a best-effort cache
  -- inside a directory the plugin owns (`.mise-nix/`).
  local tmp = cache_file .. ".tmp." .. tostring(os.time()) ..
              "." .. tostring(math.random(1000000, 9999999))
  local fout = io.open(tmp, "w")
  if not fout then return end
  fout:write(payload)
  fout:close()
  pcall(cmd.exec, "mv -f " .. shell.shquote(tmp) ..
        " " .. shell.shquote(cache_file))
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
  -- shquote() (POSIX single-quote) instead of `%q` (Lua-quote): %q escapes
  -- per Lua's rules, not the shell's, so a path containing a single quote
  -- or a `$(...)` expression could break out of the quoted word and inject
  -- arbitrary commands. shquote wraps in '...' and rewrites embedded ' as
  -- '\''.
  local ok, result = pcall(cmd.exec,
    "export MISE_NIX_HOOK_REENTRY=1; cd " .. shell.shquote(root) .. " && " ..
    "if git ls-files --error-unmatch -- " .. shell.shquote(path) .. " >/dev/null 2>&1; then " ..
    "  echo tracked; else echo untracked; fi")
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

  -- "path:.#attr" forces the path fetcher (no git filtering).
  -- ".#attr"     uses git+file when the directory is a git repo.
  local flake_ref = (allow_untracked and "path:." or ".") .. "#" .. options.flake_attr

  -- Disk cache for `nix print-dev-env` output. The command takes ~3 s to
  -- evaluate even when its result is fully deterministic given (flake.nix,
  -- flake.lock, flake_ref, flake_attr, arch); the cost dominates every
  -- shell prompt that runs `mise hook-env` (i.e. every shell mise activates).
  -- Mise's built-in `cacheable = true` / `watch_files` returned by MiseEnv
  -- is a no-op when `env_cache = false` (mise's default), and turning that
  -- on actually makes things slower in our setup, so we cache here.
  --
  -- `MISE_NIX_NO_CACHE=1` opts out for debugging or after `nix store gc`,
  -- where the cached PATH/LD_LIBRARY_PATH may point at evicted store paths.
  local cache_disabled = os.getenv("MISE_NIX_NO_CACHE") == "1"
  local cache_file = nil
  if not cache_disabled then
    -- Eagerly create profile_dir + its .gitignore here (instead of inside
    -- the slow-path shell block below) so cache hits never have to fork a
    -- shell. mkdir/write are cheap and idempotent.
    pcall(cmd.exec, "mkdir -p " .. shell.shquote(profile_dir))
    pcall(function()
      local gi = io.open(file.join_path(profile_dir, ".gitignore"), "w")
      if gi then gi:write("*\n"); gi:close() end
    end)

    local key = compute_cache_key(project_root, flake_ref, options.flake_attr)
    if key then
      cache_file = file.join_path(profile_dir, "devenv-cache." .. key .. ".json")
      local cached = load_from_cache(cache_file, profile_dir)
      if cached then
        return { env = cached, lock_file = lock_file }, nil
      end
    end
  end

  -- Capture nix's stderr in a temp file so that when print-dev-env fails
  -- we can surface the real diagnostic instead of the generic
  -- "Failed to load environment".
  -- mktemp(1) via tempdir.create_temp_file replaces os.tmpname(): the latter
  -- returns a predictable name and creates the file with the caller's umask,
  -- opening a symlink-race window (CWE-377). create_temp_file uses mktemp's
  -- atomic O_EXCL with mode 0600.
  local stderr_file = tempdir.create_temp_file("mise_nix_stderr")

  -- get_env() already wraps cmd.exec in pcall and returns nil on any
  -- failure (subprocess error, JSON decode error, …), so we don't need a
  -- second pcall here. The os.remove() below runs unconditionally on
  -- both branches — leak-free as long as the function reaches its end.
  --
  -- shell.shquote() (POSIX single-quote) instead of `%q` (Lua-quote) for
  -- every interpolated value: %q produces double-quoted shell strings
  -- which still expand `$(...)`, backticks and `${...}`. flake_ref
  -- ultimately includes options.flake_attr, which a project's mise.toml
  -- can set; without single-quoting, a malicious `[tools]` entry could
  -- inject arbitrary commands here. shquote wraps in '...' and rewrites
  -- embedded ' as '\''.
  ---@type DevEnv?
  local env = get_env(([=[
    set -eu

    PROFILE_DIR=%s
    LOCK_FILE=%s
    FLAKE_REF=%s
    STDERR=%s

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

    # Pin the freshly-built profile as a gc-root so subsequent
    # `nix-collect-garbage` invocations (notably the one wired into the
    # ops-cli image build under NIX_CLEANUP=true) cannot evict the
    # devShell's transitive store paths. Without this, every `./ops.sh
    # build` would silently delete django/python3/... from the shared
    # ops-share-nix volume and the user's PATH would resolve to broken
    # /nix/store/* segments at the next shell start.
    #
    # The gc-root is a plain symlink in /nix/var/nix/gcroots/per-user/<uid>/
    # pointing at the resolved store path. nix-collect-garbage scans
    # gcroots/ recursively and considers any symlink target reachable.
    # We re-point the link on every refresh so it always tracks the
    # current profile generation; stale entries from older flake.lock
    # revisions are overwritten in place by the same project hash.
    _gc_target=$(readlink -f "${PROFILE_DIR}/profile" 2>/dev/null || true)
    if [ -n "${_gc_target}" ] && [ -e "${_gc_target}" ]; then
      _gc_uid=$(id -u)
      _gc_dir="/nix/var/nix/gcroots/per-user/${_gc_uid}"
      _gc_key=$(printf '%%s' "${PROFILE_DIR}" | sha256sum | cut -c1-16)
      mkdir -p "${_gc_dir}" 2>/dev/null || true
      ln -sfn "${_gc_target}" "${_gc_dir}/mise-nix-${_gc_key}" 2>>"${STDERR}" || true
    fi
  ]=]):format(shell.shquote(profile_dir),
              shell.shquote(lock_file),
              shell.shquote(flake_ref),
              shell.shquote(stderr_file)))

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

  -- Cache the freshly-evaluated devenv so the next shell prompt can skip
  -- nix entirely. cache_file is nil when caching is disabled (NO_CACHE) or
  -- when key computation failed; save_to_cache() is itself a no-op on any
  -- write error (best-effort).
  if cache_file then
    save_to_cache(cache_file, env)
  end

  return { env = env, lock_file = lock_file }, nil
end

return {
  find_project_root = find_project_root,
  load_env = load_env,
  -- Exposed for tests; not part of the public plugin API.
  _compute_cache_key = compute_cache_key,
  _load_from_cache = load_from_cache,
  _save_to_cache = save_to_cache,
}
