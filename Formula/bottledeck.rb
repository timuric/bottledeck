class Bottledeck < Formula
  desc "Zero-touch multi-harness telemetry, Ratatui dashboard, and bottleneck analyzer for coding agents"
  homepage "https://github.com/timuric/bottledeck"
  version "0.3.0"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/timuric/bottledeck/releases/download/v0.3.0/bottledeck-v0.3.0-aarch64-apple-darwin.tar.gz"
      sha256 "615230423988c13d8f21dd0398a23a023aeecc0a6a289e38b745d5814ac9306d"
    else
      url "https://github.com/timuric/bottledeck/releases/download/v0.3.0/bottledeck-v0.3.0-x86_64-apple-darwin.tar.gz"
      sha256 "2d0ae6dc95f87bc94f8329f415241a9ae03404fc5bc43f5cdcf66d6899e86c95"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/timuric/bottledeck/releases/download/v0.3.0/bottledeck-v0.3.0-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "bed48cff6203ee61da4330cb7a35fa9a2c69b1240bf2852c2027587958031fc1"
    else
      url "https://github.com/timuric/bottledeck/releases/download/v0.3.0/bottledeck-v0.3.0-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "d5f1f3b07c71bd8c150fb0fde9fa1345c9afd33aaefd50b273d5318e5750d521"
    end
  end

  def install
    bin.install "bottledeck"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/bottledeck --version")
  end
end
