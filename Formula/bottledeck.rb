class Bottledeck < Formula
  desc "Zero-touch multi-harness telemetry, Ratatui dashboard, and bottleneck analyzer for coding agents"
  homepage "https://github.com/timuric/bottledeck"
  version "0.4.0"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/timuric/bottledeck/releases/download/v0.4.0/bottledeck-v0.4.0-aarch64-apple-darwin.tar.gz"
      sha256 "e48fe5b3bf9c17e231d2d6931fa70748ba66a19f49e7ccf54993a43cd1fd2e4e"
    else
      url "https://github.com/timuric/bottledeck/releases/download/v0.4.0/bottledeck-v0.4.0-x86_64-apple-darwin.tar.gz"
      sha256 "9c930f8764f014166265cd0eec5fd4ed23dbaa30d2195cb02328aa7bfa1abb23"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/timuric/bottledeck/releases/download/v0.4.0/bottledeck-v0.4.0-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "c8209067d02b2abf3db66a970934944a78eb232fed82ee41c07c345565006136"
    else
      url "https://github.com/timuric/bottledeck/releases/download/v0.4.0/bottledeck-v0.4.0-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "30e71fdd2d8758e0f56fdfe64db091373dd80ef3b6c388b364319495192d53a5"
    end
  end

  def install
    bin.install "bottledeck"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/bottledeck --version")
  end
end
