class Bottledeck < Formula
  desc "Zero-touch multi-harness telemetry, Ratatui dashboard, and bottleneck analyzer for coding agents"
  homepage "https://github.com/timuric/bottledeck"
  version "0.4.1"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/timuric/bottledeck/releases/download/v0.4.1/bottledeck-v0.4.1-aarch64-apple-darwin.tar.gz"
      sha256 "fbda92397a8d74771eeb90b388f98aa715bc78bef73ddb8b7eb9e63d4e4cd759"
    else
      url "https://github.com/timuric/bottledeck/releases/download/v0.4.1/bottledeck-v0.4.1-x86_64-apple-darwin.tar.gz"
      sha256 "eff6b9d461d970131100a74bb75c6fd57b400d34bd57f6cefb00e100df7feaf9"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/timuric/bottledeck/releases/download/v0.4.1/bottledeck-v0.4.1-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "33a5ace6f62a25fe20cd08bb026691b477e6afff1e2b656f61c34eadd8c6e7f1"
    else
      url "https://github.com/timuric/bottledeck/releases/download/v0.4.1/bottledeck-v0.4.1-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "df01945ee6607ef9b7747f9cfd5fb8a781318a32da263b5510b2da60441fdb60"
    end
  end

  def install
    bin.install "bottledeck"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/bottledeck --version")
  end
end
