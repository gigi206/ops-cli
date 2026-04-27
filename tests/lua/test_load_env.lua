-- Tests for utils.load_env's git-tracked / MISE_NIX_ALLOW_UNTRACKED branch.
--
-- Four logical branches: tracked × flag-set. Only the (untracked + no-flag)
-- branch must surface the 4-line "not tracked by git" diagnostic — the
-- regression we want to lock down (regenerated stderr noise leaked at first
-- launch when the warm-path bashrc had not exported MISE_NIX_ALLOW_UNTRACKED
-- yet, see scripts/ops-bashrc and ops.sh `_agent_cmd` history).
--
-- We don't try to drive `load_env` all the way to its success return: the
-- happy path requires a working `nix print-dev-env`, a real flake, a temp
-- file, and a JSON cache writer. Those are out of scope for a unit test;
-- exercising them belongs to test_image_integration.bats. Here we focus on
-- the "early return with errs" branch and confirm that the diagnostic is
-- emitted iff the relevant inputs are met.

local h = require("spec_helpers")
local utils = require("utils")

io.write("== utils.load_env (allow_untracked × tracked branches) ==\n")

-- Helper: build a (real_getenv-aware) os.getenv mock that returns the user
-- supplied table for known keys and falls back to the original os.getenv
-- for everything else (so mise's other env probes — TMPDIR, USER, etc. —
-- keep working). The keys the test wants to control must be listed in
-- `handled_keys` even when the desired value is nil (force-unset),
-- because Lua tables can't distinguish "key not present" from "key set to
-- nil" with a plain `overrides[key] ~= nil` check — and the test runner
-- itself may have e.g. MISE_NIX_ALLOW_UNTRACKED=1 in its real environment,
-- which would silently bypass the test's intent without this guard.
local function make_getenv(handled_keys, overrides)
  local real = os.getenv
  local handled = {}
  for _, k in ipairs(handled_keys) do handled[k] = true end
  return function(key)
    if handled[key] then return overrides[key] end
    return real(key)
  end
end

local CONTROLLED_KEYS = {
  "MISE_NIX_HOOK_REENTRY",
  "MISE_NIX_ALLOW_UNTRACKED",
  "MISE_NIX_NO_CACHE",
}

-- Helper: drive load_env() with a synthetic project root and a controlled
-- (allow_untracked, is_tracked) pair. Returns (result, errs).
local function run_load_env(opts)
  local result, errs
  h.with_mocks({
    -- file.exists: lock file present so we get past the "Lock file does
    -- not exist" early return; .git presence depends on `is_tracked`
    -- semantics — when we want is_git_tracked() to invoke git, .git must
    -- be reported present.
    { h.file, "exists", function(path)
        if path:match("flake%.nix$") then return true end
        if path:match("flake%.lock$") then return true end
        if path:match("%.git$") then return true end
        return false
      end },
    -- cmd.exec is hit by find_project_root (`pwd`) and by is_git_tracked
    -- (`git ls-files …`). We dispatch on substring match.
    { h.cmd, "exec", function(c)
        if c == "pwd" then return "/tmp/fake-project\n" end
        if c:match("git ls%-files") then
          return opts.is_tracked and "tracked\n" or "untracked\n"
        end
        return ""
      end },
    -- Replace os.getenv only; restore in afterwards via with_mocks.
    { os, "getenv", make_getenv(CONTROLLED_KEYS, {
        MISE_NIX_HOOK_REENTRY    = nil,  -- never reentrant in tests
        MISE_NIX_ALLOW_UNTRACKED = opts.allow_untracked and "1" or nil,
        MISE_NIX_NO_CACHE        = "1",  -- skip the disk cache path
      }) },
  }, function()
    -- The happy path runs `nix print-dev-env`, mktemp, JSON decode etc.
    -- We don't care about that here — only about whether the
    -- "not tracked by git" diagnostic is emitted before the function
    -- bails on the (mocked) downstream failure. pcall absorbs the
    -- inevitable "mktemp failed" / nix-not-found error so the assertion
    -- can still inspect what came back.
    pcall(function() result, errs = utils.load_env({}) end)
  end)
  return result, errs
end

local NOT_TRACKED_MSG = "not tracked by git"

-- (4) untracked + no flag → MUST emit the 4-line diagnostic, and the
--     first line must contain "not tracked by git" so the user gets the
--     actionable hint right away.
h.test("load_env: untracked + no MISE_NIX_ALLOW_UNTRACKED → emits the 4-line diagnostic", function()
  local result, errs = run_load_env({ is_tracked = false, allow_untracked = false })
  h.assert_eq(result, nil, "expected nil result on the untracked-no-flag branch")
  h.assert_true(errs ~= nil, "expected non-nil errs table")
  h.assert_eq(#errs, 4, "expected exactly 4 diagnostic lines")
  h.assert_true(errs[1]:find(NOT_TRACKED_MSG, 1, true) ~= nil,
    "first diagnostic line must mention 'not tracked by git'")
  h.assert_true(errs[3]:find("git %-C") ~= nil and errs[3]:find("add %-fN") ~= nil,
    "third line must include the 'git -C … add -fN' fix command")
  h.assert_true(errs[4]:find("MISE_NIX_ALLOW_UNTRACKED=1", 1, true) ~= nil,
    "fourth line must mention the MISE_NIX_ALLOW_UNTRACKED=1 bypass")
end)

-- (3) untracked + flag set → MUST NOT emit the "not tracked" diagnostic.
--     The function may still fail later (no real nix), but the failure
--     must not be the git-tracked one.
h.test("load_env: untracked + MISE_NIX_ALLOW_UNTRACKED=1 → diagnostic is suppressed", function()
  local _, errs = run_load_env({ is_tracked = false, allow_untracked = true })
  if errs ~= nil then
    for _, line in ipairs(errs) do
      h.assert_true(line:find(NOT_TRACKED_MSG, 1, true) == nil,
        "errs must NOT contain the 'not tracked by git' line; got: " .. line)
    end
  end
end)

-- (2) tracked + no flag → diagnostic suppressed (the file IS tracked, so
--     the check passes regardless of the flag).
h.test("load_env: tracked + no flag → diagnostic is suppressed", function()
  local _, errs = run_load_env({ is_tracked = true, allow_untracked = false })
  if errs ~= nil then
    for _, line in ipairs(errs) do
      h.assert_true(line:find(NOT_TRACKED_MSG, 1, true) == nil,
        "errs must NOT contain the 'not tracked by git' line; got: " .. line)
    end
  end
end)

-- (1) tracked + flag set → diagnostic suppressed (both gates open).
h.test("load_env: tracked + MISE_NIX_ALLOW_UNTRACKED=1 → diagnostic is suppressed", function()
  local _, errs = run_load_env({ is_tracked = true, allow_untracked = true })
  if errs ~= nil then
    for _, line in ipairs(errs) do
      h.assert_true(line:find(NOT_TRACKED_MSG, 1, true) == nil,
        "errs must NOT contain the 'not tracked by git' line; got: " .. line)
    end
  end
end)

-- Re-entry guard: when MISE_NIX_HOOK_REENTRY=1 is set, load_env returns nil
-- (no errs) immediately so the recursive shim invocation doesn't spin. Not
-- strictly part of the tracked/untracked matrix but it shares the same
-- env-driven control flow and is a known footgun if the guard regresses.
h.test("load_env: MISE_NIX_HOOK_REENTRY=1 → silent early return", function()
  local result, errs
  h.with_mocks({
    { os, "getenv", make_getenv({ "MISE_NIX_HOOK_REENTRY" }, { MISE_NIX_HOOK_REENTRY = "1" }) },
  }, function()
    result, errs = utils.load_env({})
  end)
  h.assert_eq(result, nil, "expected nil result on reentry")
  h.assert_eq(errs, nil, "expected nil errs on reentry (no diagnostic surfaced)")
end)
