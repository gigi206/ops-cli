-- Project-wide luacheck configuration. Picked up automatically by both
-- `mise run lint` and the CI step (no extra flags required on the
-- command line beyond the path).
--
-- Globals injected by the vfox host at plugin load time, not declared
-- by the Lua sources themselves.
globals = {"PLUGIN", "RUNTIME"}

-- types.lua holds only EmmyLua ---@meta annotations, which luacheck
-- (correctly) flags as unused declarations.
exclude_files = {"mise/types.lua"}

-- We don't enforce a line-length limit; mise-nix upstream doesn't either.
max_line_length = false

-- vfox plugin hooks always carry a `self` parameter for symmetry, even
-- when the body doesn't reference it. Treating that as an error would
-- force every hook to add `_ = self` boilerplate.
unused_args = false

-- Cosmetic / stylistic warnings we accept project-wide:
ignore = {
    "211",  -- unused local variable (e.g. require()d helpers kept for parity
            -- with upstream files we have not modified)
    "421",  -- shadowing local definition (recurring pattern in long
            -- functions; refactoring across the upstream MIT files to
            -- dedupe `ok` locals carries more risk than it removes)
    "431",  -- shadowing upvalue (same rationale as 421)
    "542",  -- empty if branch (intentional "skip" branches in env hooks)
    "611",  -- line contains only whitespace
    "612",  -- line contains trailing whitespace
    "613",  -- trailing whitespace in string
}
