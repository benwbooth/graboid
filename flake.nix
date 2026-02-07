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
          ];

          RUST_LOG = "info";
          GRABOID_RS_BIND_ADDR = "127.0.0.1:8000";
        };

        formatter = pkgs.nixfmt-rfc-style;
      }
    );
}
