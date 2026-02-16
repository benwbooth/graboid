{
  description = "Graboid Rust rewrite with reproducible dev environment";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; };

        graboidRs = pkgs.rustPlatform.buildRustPackage {
          pname = "graboid-rs";
          version = "0.1.0";
          src = ./graboid-rs;

          cargoLock = {
            lockFile = ./graboid-rs/Cargo.lock;
          };

          nativeBuildInputs = [
            pkgs.pkg-config
            pkgs.cmake
          ];
          buildInputs = [
            pkgs.openssl
            pkgs.samba
            pkgs.samba.dev
            pkgs.libssh2
            pkgs.zlib
          ];

          doCheck = false;
        };
      in
      {
        packages.default = graboidRs;

        apps.default = flake-utils.lib.mkApp {
          drv = graboidRs;
        };

        devShells.default = pkgs.mkShell {
          packages = with pkgs; [
            rustc
            cargo
            rustfmt
            clippy
            rust-analyzer
            pkg-config
            pkgconf
            cmake
            watchexec
            sqlite
            trunk
            wasm-bindgen-cli
            binaryen
            llvmPackages.lld
            nodejs_22
            chromium
            deluge
            samba
            samba.dev
            openssl
            libssh2
            zlib
          ];

          # Keep flake inputs in closure so GC doesn't collect them
          FLAKE_INPUTS = builtins.concatStringsSep ":" [ "${nixpkgs}" "${flake-utils}" ];

          RUST_LOG = "info";
          GRABOID_RS_BIND_ADDR = "127.0.0.1:8000";

          shellHook = ''
            export NPM_CONFIG_PREFIX="$HOME/.npm-global"
            export PATH="$NPM_CONFIG_PREFIX/bin:$PATH"
            if ! command -v chrome-devtools-mcp &>/dev/null; then
              echo "Installing chrome-devtools-mcp globally..."
              npm install -g chrome-devtools-mcp 2>/dev/null
            fi
          '';
        };

        formatter = pkgs.nixfmt-rfc-style;
      }
    );
}
