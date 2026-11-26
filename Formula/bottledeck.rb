class Bottledeck < Formula
  desc "Zero-touch multi-harness telemetry, Ratatui dashboard, and bottleneck analyzer for coding agents"
  homepage "https://github.com/timuric/bottledeck"
  version "0.2.0"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/timuric/bottledeck/releases/download/v0.2.0/bottledeck-v0.2.0-aarch64-apple-darwin.tar.gz"
      sha256 "0f718ff197768b0692ac5246a0facea47dd0e4f26e067d69748d9f04965bcaa3"
    else
      url "https://github.com/timuric/bottledeck/releases/download/v0.2.0/bottledeck-v0.2.0-x86_64-apple-darwin.tar.gz"
      sha256 "73dbc5c9b47a510c173e404bc8cca0731ac3950c109a9128e0abe1e1f052a53b"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/timuric/bottledeck/releases/download/v0.2.0/bottledeck-v0.2.0-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "993c6837fc37deee7ae30c473ad6e121ff56d85994afa0144b7c2d701e586754"
    else
      url "https://github.com/timuric/bottledeck/releases/download/v0.2.0/bottledeck-v0.2.0-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "0e19c4d32469ca9274f07788772e8020be7db92c60f50a3090106482ec7bae3e"
    end
  end

  def install
    bin.install "bottledeck"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/bottledeck --version")
  end
end
