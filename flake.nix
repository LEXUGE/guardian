{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    rust-overlay.url = "github:oxalica/rust-overlay";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs =
    {
      self,
      nixpkgs,
      rust-overlay,
      flake-utils,
      ...
    }:
    flake-utils.lib.eachSystem [ "x86_64-linux" "aarch64-linux" ] (
      system:
      let
        overlays = [ (import rust-overlay) ];
        pkgs = import nixpkgs {
          inherit system overlays;
        };
        rust = pkgs.rust-bin.stable.latest.default.override {
          extensions = [
            "rust-src"
            "rust-analyzer"
          ];
        };
        rustPlatform = pkgs.makeRustPlatform {
          cargo = rust;
          rustc = rust;
        };
        runtimeDependencies = with pkgs; [
          gvisor
          podman
        ];
        guardian-cli = rustPlatform.buildRustPackage {
          pname = "guardian-cli";
          version = "0.1.0";
          src = ./.;

          cargoLock.lockFile = ./Cargo.lock;
          cargoBuildFlags = [
            "--package"
            "guardian-cli"
          ];

          # The test suite contains a live Podman integration test.
          doCheck = false;

          nativeBuildInputs = [ pkgs.makeWrapper ];
          # installPhase = ''
          #   install -Dm755 target/release/guardian $out/bin/guardian
          # '';
          postInstall = ''
            wrapProgram "$out/bin/guardian" \
              --prefix PATH : "${pkgs.lib.makeBinPath runtimeDependencies}"
          '';

          meta = {
            description = "Secure, auditable computing environment for AI agents";
            mainProgram = "guardian";
            platforms = pkgs.lib.platforms.linux;
          };
        };
      in
      {
        packages = {
          default = guardian-cli;
          inherit guardian-cli;
        };

        devShells.default =
          with pkgs;
          mkShell {
            buildInputs = [
              openssl
              pkg-config
              eza
              fd
              rust
            ]
            ++ runtimeDependencies;

            shellHook = ''
              alias ls=eza
              alias find=fd
            '';
          };
      }
    );
}
