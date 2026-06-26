# Homebrew formula TEMPLATE for CyberShell Copilot.
#
# This is NOT a tested, tap-ready formula. After publishing the sdist to PyPI,
# fill in the url + sha256, then test on macOS via a personal tap before relying
# on it. See packaging/README.md and HANDOFF.md.
class CybershellCopilot < Formula
  include Language::Python::Virtualenv

  desc "Offline cybersecurity-aware terminal command risk scorer and guardrails"
  homepage "https://github.com/waltr0/smartTerminal"
  url "https://files.pythonhosted.org/packages/source/c/cybershell-copilot/cybershell_copilot-0.2.0.tar.gz"
  sha256 "REPLACE_WITH_PUBLISHED_SDIST_SHA256"
  license "MIT"

  depends_on "python@3.12"

  def install
    virtualenv_install_with_resources
  end

  test do
    assert_match "cybershell", shell_output("#{bin}/cybershell --version")
  end
end
