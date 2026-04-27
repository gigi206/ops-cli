-- SPDX-License-Identifier: Apache-2.0
-- Copyright (c) 2024 Jose Badeau (https://github.com/jbadeau/mise-nix)

-- Centralized logging with consistent formatting
local M = {}

function M.info(msg)  print("ℹ️ " .. msg) end
function M.step(msg)  print("🔨 " .. msg) end
function M.done(msg)  print("✅ " .. msg) end
function M.warn(msg)  print("⚠️ " .. msg) end
function M.fail(msg)  print("❌ " .. msg) end
function M.pack(msg)  print("📦 " .. msg) end
function M.find(msg)  print("🔍 " .. msg) end
function M.tool(msg)  print("🔧 " .. msg) end
function M.hint(msg)  print("💡 " .. msg) end
-- True when MISE_DEBUG / MISE_VERBOSE is set. Callers that build expensive
-- debug payloads (running shell commands purely to log their output) should
-- gate the whole block on `if logger.is_debug()` so the work isn't done at
-- all in non-debug runs.
function M.is_debug()
  return os.getenv("MISE_DEBUG") ~= nil or os.getenv("MISE_VERBOSE") ~= nil
end

function M.debug(msg)
  if M.is_debug() then
    print("🐛 " .. msg)
  end
end

return M