# Homebrew formula for Mantis Hack.
#
# Until this lands in homebrew-core, distribute via a personal tap:
#
#   git init homebrew-mantis
#   cp Formula/mantishack.rb homebrew-mantis/Formula/
#   gh repo create deonmenezes/homebrew-mantis --public --source=homebrew-mantis --push
#
# Then users run:
#
#   brew tap deonmenezes/mantis
#   brew install mantishack
#
# Bump procedure on each tagged release:
#   1. git tag v<X.Y.Z> && git push --tags
#   2. curl -sL "https://github.com/deonmenezes/mantishack/archive/refs/tags/v<X.Y.Z>.tar.gz" | shasum -a 256
#   3. Update `url` + `sha256` below.

class Mantishack < Formula
  desc "Offensive-security daemon — 7-phase FSM bug bounty harness (authorized testing only)"
  homepage "https://github.com/deonmenezes/mantishack"
  url "https://github.com/deonmenezes/mantishack/archive/refs/tags/v0.0.7.tar.gz"
  sha256 "7df46c5452ee03b996a6959132d2cefd11ae12269bed245cba2d8c0238472cff"
  license any_of: ["Apache-2.0", "MIT"]
  head "https://github.com/deonmenezes/mantishack.git", branch: "main"

  depends_on "rust" => :build

  def install
    system "cargo", "install", *std_cargo_args(path: "crates/mantis-cli")
    system "cargo", "install", *std_cargo_args(path: "crates/mantis-daemon")

    # Bundle the plugin directory so `mantis init` can wire it into
    # ~/.claude/plugins/mantis (and equivalent for codex / opencode).
    (share/"mantis").install "plugin"
  end

  def caveats
    <<~EOS
      Mantis is installed. Next steps:

        mantis             # interactive setup screen
        mantis init        # wire the Claude / Codex / OpenCode plugin + MCP server
        mantis-daemon      # start the daemon

      The bundled plugin sources live at:
        #{opt_share}/mantis/plugin

      Authorized testing only. Read the disclaimer:
        https://github.com/deonmenezes/mantishack/blob/main/DISCLAIMER_BOB_STYLE.md
    EOS
  end

  test do
    assert_match "mantis", shell_output("#{bin}/mantis --help")
    assert_match "mantis-daemon", shell_output("#{bin}/mantis-daemon --help")
  end
end
