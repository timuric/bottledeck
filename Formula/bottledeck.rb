class Bottledeck < Formula
  desc "Zero-touch multi-harness telemetry, Ratatui dashboard, and bottleneck analyzer for coding agents"
  homepage "https://github.com/timuric/bottledeck"
  version "0.5.0"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/timuric/bottledeck/releases/download/v0.5.0/bottledeck-v0.5.0-aarch64-apple-darwin.tar.gz"
      sha256 "1749af5c627c258fc692c8171d5bd31672128384177eea81f164dc1a34177509"
    else
      url "https://github.com/timuric/bottledeck/releases/download/v0.5.0/bottledeck-v0.5.0-x86_64-apple-darwin.tar.gz"
      sha256 "9eccdd375fdd47570e25a34579eb0f401770df1bc4c5608c7c3b30f919c98ff8"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/timuric/bottledeck/releases/download/v0.5.0/bottledeck-v0.5.0-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "5593a3387988689669ad917995c46e6a2eafa459473da19fcff6155b89abc343"
    else
      url "https://github.com/timuric/bottledeck/releases/download/v0.5.0/bottledeck-v0.5.0-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "fed767fcbaee37e10e2c6abeabce78fb7e167f715d7f4636c4e14447beb30d24"
    end
  end

  def install
    bin.install "bottledeck"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/bottledeck --version")
  end
end
