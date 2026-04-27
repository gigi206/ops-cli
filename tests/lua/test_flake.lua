local h = require("spec_helpers")
local flake = require("flake")

io.write("== flake.is_reference / convert_custom_git_prefix ==\n")

h.test("is_reference accepts standard nix flake refs", function()
  h.assert_true(flake.is_reference("github:owner/repo#pkg"))
  h.assert_true(flake.is_reference("gitlab:group/project#pkg"))
  h.assert_true(flake.is_reference("git+https://example.com/repo.git#pkg"))
  h.assert_true(flake.is_reference("git+ssh://git@example.com/repo.git#pkg"))
  h.assert_true(flake.is_reference("path:/abs/path#pkg"))
  h.assert_true(flake.is_reference("file:/abs/file#pkg"))
end)

h.test("is_reference accepts the nixpkgs# shorthand", function()
  h.assert_true(flake.is_reference("nixpkgs#hello"))
end)

h.test("is_reference accepts owner/repo shorthand with #", function()
  h.assert_true(flake.is_reference("nixos/nixpkgs#hello"))
end)

h.test("is_reference accepts custom + prefixes", function()
  h.assert_true(flake.is_reference("github+owner/repo#pkg"))
  h.assert_true(flake.is_reference("gitlab+group/project#pkg"))
  h.assert_true(flake.is_reference("vscode+install=vscode-extensions.foo.bar"))
  h.assert_true(flake.is_reference("vscode-extensions.foo.bar"))
end)

h.test("is_reference accepts relative and absolute path flakes", function()
  h.assert_true(flake.is_reference("./local-flake#pkg"))
  h.assert_true(flake.is_reference("../sibling#pkg"))
  h.assert_true(flake.is_reference("/abs/local-flake#pkg"))
end)

h.test("is_reference rejects plain package names", function()
  h.assert_false(flake.is_reference("ripgrep"))
  h.assert_false(flake.is_reference("nodejs@20"))
end)

h.test("is_reference rejects nil and non-strings", function()
  h.assert_false(flake.is_reference(nil))
  h.assert_false(flake.is_reference(123))
end)

h.test("convert_custom_git_prefix rewrites github+ -> github:", function()
  h.assert_eq(flake.convert_custom_git_prefix("github+owner/repo"), "github:owner/repo")
end)

h.test("convert_custom_git_prefix rewrites gitlab+ -> gitlab:", function()
  h.assert_eq(flake.convert_custom_git_prefix("gitlab+group/project"), "gitlab:group/project")
end)

h.test("convert_custom_git_prefix rewrites https+ -> git+https://", function()
  h.assert_eq(flake.convert_custom_git_prefix("https+example.com/repo.git"),
              "git+https://example.com/repo.git")
end)

h.test("convert_custom_git_prefix rewrites ssh+host -> git+ssh://git@host", function()
  -- Without an explicit user@ prefix the helper inserts git@ for SSH.
  h.assert_eq(flake.convert_custom_git_prefix("ssh+example.com/repo.git"),
              "git+ssh://git@example.com/repo.git")
end)

h.test("convert_custom_git_prefix preserves explicit user@ ssh", function()
  h.assert_eq(flake.convert_custom_git_prefix("ssh+user@example.com/repo.git"),
              "git+ssh://user@example.com/repo.git")
end)

h.test("convert_custom_git_prefix is a passthrough for unknown values", function()
  h.assert_eq(flake.convert_custom_git_prefix("1.2.3"), "1.2.3")
  h.assert_eq(flake.convert_custom_git_prefix(nil), nil)
end)
