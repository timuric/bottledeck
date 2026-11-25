class Bottledeck < Formula
  desc "Zero-touch multi-harness telemetry, Ratatui dashboard, and bottleneck analyzer for coding agents"
  homepage "https://github.com/timuric/bottledeck"
  version "0.1.0"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/timuric/bottledeck/releases/download/v0.1.0/bottledeck-v0.1.0-aarch64-apple-darwin.tar.gz"
      sha256 "910d34f60b562cb3f8e92caa3b44144113076ddc09e7874e2cfc1caa238ed317"
    else
      url "https://github.com/timuric/bottledeck/releases/download/v0.1.0/bottledeck-v0.1.0-x86_64-apple-darwin.tar.gz"
      sha256 "ed130f0cc1a24679a4f9208002105d6ca726346786d9aaf1f6cf5205829d9502"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/timuric/bottledeck/releases/download/v0.1.0/bottledeck-v0.1.0-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "f459b91f829d56add4e46f363777ce0e89162bdc1e99d36d2edfc7752ca6d73c"
    else
      url "https://github.com/timuric/bottledeck/releases/download/v0.1.0/bottledeck-v0.1.0-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "37feae975b6e9b7962293750f75c8f302850220456d8322b5c8f60b292a8de4c"
    end
  end

  def install
    bin.install "bottledeck"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/bottledeck --version")
  end
end
