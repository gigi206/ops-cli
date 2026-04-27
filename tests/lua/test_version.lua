local h = require("spec_helpers")
local version = require("version")

io.write("== version.parse_version / is_valid / is_compatible ==\n")

h.test("is_valid accepts standard semver", function()
  h.assert_true(version.is_valid("1.2.3"))
  h.assert_true(version.is_valid("17.0.14+7"))
  h.assert_true(version.is_valid("v2024-04-01"))
end)

h.test("is_valid rejects empty and non-strings", function()
  h.assert_false(version.is_valid(""))
  h.assert_false(version.is_valid(nil))
  h.assert_false(version.is_valid(123))
  h.assert_false(version.is_valid("ver with spaces"))
end)

h.test("parse_version classifies a basic semver", function()
  local p = version.parse_version("1.2.3")
  h.assert_eq(p.type, "semantic")
  h.assert_eq(p.major, 1); h.assert_eq(p.minor, 2); h.assert_eq(p.patch, 3)
  h.assert_eq(p.pre, "")
end)

h.test("parse_version captures pre-release suffix", function()
  local p = version.parse_version("17.0.14+7")
  h.assert_eq(p.type, "semantic")
  h.assert_eq(p.major, 17); h.assert_eq(p.patch, 14)
  h.assert_eq(p.pre, "7")
end)

h.test("parse_version falls back to numeric extraction", function()
  local p = version.parse_version("2024.04")
  h.assert_eq(p.type, "numeric")
  h.assert_eq(p.major, 2024); h.assert_eq(p.minor, 4)
end)

h.test("parse_version falls back to opaque for git hashes (no digits)", function()
  -- Use a digit-free hash so `gmatch("%d+")` produces no numeric tokens
  -- and parse_version reaches the `type = "string"` fallback. A hash that
  -- happens to contain a digit (e.g. "abcdef0") would be classified as
  -- "numeric" with major=0 — semantically equivalent for ordering, but
  -- not what this branch is testing.
  local p = version.parse_version("abcdefa")
  h.assert_eq(p.type, "string")
  h.assert_eq(p.major, 0)
end)

h.test("parse_semver echoes the pre suffix from parse_version", function()
  local p = version.parse_semver("1.0.0-rc1")
  h.assert_eq(p.major, 1); h.assert_eq(p.minor, 0); h.assert_eq(p.patch, 0)
  h.assert_eq(p.pre, "rc1")
end)

h.test("find_latest_stable skips pre-releases", function()
  -- Order matters: function walks the list from the end. The last STABLE
  -- entry is "1.2.3"; we expect it to win over the trailing "1.3.0-rc1".
  local v = version.find_latest_stable({"1.0.0", "1.2.3", "1.3.0-rc1"})
  h.assert_eq(v, "1.2.3")
end)

h.test("is_compatible matches OS/arch tokens", function()
  h.assert_true(version.is_compatible("Linux x86_64", "linux", "amd64"))
  h.assert_false(version.is_compatible("MacOS only (Intel only)", "linux", "amd64"))
  h.assert_false(version.is_compatible("Linux ARM only", "linux", "amd64"))
  h.assert_false(version.is_compatible("Linux Intel only", "linux", "arm64"))
  h.assert_true(version.is_compatible(nil, "linux", "amd64") == false)
end)

h.test("filter_compatible_versions keeps matching releases", function()
  local releases = {
    { version = "1.0", platforms_summary = "Linux x86_64" },
    { version = "1.1", platforms_summary = "MacOS Intel only" },
    { version = "1.2", platforms_summary = "Linux x86_64" },
  }
  local kept = version.filter_compatible_versions(releases, "linux", "amd64")
  h.assert_eq(#kept, 2)
  h.assert_eq(kept[1].version, "1.0")
  h.assert_eq(kept[2].version, "1.2")
end)

h.test("resolve_alias defaults `latest` to last release", function()
  local releases = { { version = "1.0" }, { version = "1.1" } }
  h.assert_eq(version.resolve_alias("latest", releases).version, "1.1")
  h.assert_eq(version.resolve_alias("", releases).version, "1.1")
  h.assert_eq(version.resolve_alias(nil, releases).version, "1.1")
end)

h.test("resolve_alias finds an exact version", function()
  local releases = { { version = "1.0" }, { version = "1.1" } }
  h.assert_eq(version.resolve_alias("1.0", releases).version, "1.0")
end)

h.test("resolve_alias returns nil for an unknown version", function()
  local releases = { { version = "1.0" } }
  h.assert_eq(version.resolve_alias("9.9", releases), nil)
end)
