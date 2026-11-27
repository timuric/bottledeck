class Bottledeck < Formula
  desc "Zero-touch multi-harness telemetry, Ratatui dashboard, and bottleneck analyzer for coding agents"
  homepage "https://github.com/timuric/bottledeck"
  version "0.4.2"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/timuric/bottledeck/releases/download/v0.4.2/bottledeck-v0.4.2-aarch64-apple-darwin.tar.gz"
      sha256 "c643851c41d74bc70e019fec5a24fdc5837d054f368a8d1f62b7652535da1f90"
    else
      url "https://github.com/timuric/bottledeck/releases/download/v0.4.2/bottledeck-v0.4.2-x86_64-apple-darwin.tar.gz"
      sha256 "b90c30838d52137694182a8765903546c1e1562883ce5b814b73f8d5d2b4fa5a"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/timuric/bottledeck/releases/download/v0.4.2/bottledeck-v0.4.2-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "9e7336163e3f1f13b2777e61eeabb07b362bf82db42d8be449a4676a84a9ac7b"
    else
      url "https://github.com/timuric/bottledeck/releases/download/v0.4.2/bottledeck-v0.4.2-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "52d9d3735ab7fb6968c4798fe7b2960d81facd7ca9c32f9c6f1e050b7a679caa"
    end
  end

  def install
    bin.install "bottledeck"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/bottledeck --version")
  end
end
