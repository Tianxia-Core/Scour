# ffp: FFP-NIX-FLAKE declarative nix
{
  description = "Scour v1.2.0 — Scour Autonomous Signal Harvester, Security-Hardening Scour/Miner & GitHub Repo Update Sentinel";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.05";
  };

  outputs = { self, nixpkgs, ... }:
    let
      supportedSystems = [ "x86_64-linux" "aarch64-linux" ];
      forAllSystems = nixpkgs.lib.genAttrs supportedSystems;
      artifactMeta = {
        "x86_64-linux" = {
          url = "https://github.com/Tianxia-Core/Scour/releases/download/v1.2.0/scour-v1.2.0-linux-x86_64";
          sha256 = "f1b2ab6b037f5a867867b502c51c9e07aa7b72f72cdfe73a076ba43bbd47cba7";
        };
        "aarch64-linux" = {
          url = "https://github.com/Tianxia-Core/Scour/releases/download/v1.2.0/scour-v1.2.0-linux-aarch64";
          sha256 = "16ec2d7f8915deaed96a81e98c0d1ded4b515c26aaf24f0d38114a86c7220781";
        };
      };
      mkSovereignPkg = pkgs: system:
        let
          metaInfo = artifactMeta.${system};
        in
        pkgs.stdenvNoCC.mkDerivation {
          pname = "scour";
          version = "1.2.0";
          src = pkgs.fetchurl {
            inherit (metaInfo) url sha256;
          };
          dontUnpack = true;
          installPhase = ''
            runHook preInstall
            mkdir -p $out/bin
            install -m 0755 $src $out/bin/scour
            runHook postInstall
          '';
          meta = with pkgs.lib; {
            description = "Scour Autonomous Signal Harvester, Security-Hardening Scour/Miner & GitHub Repo Update Sentinel";
            homepage = "https://rasaxmachina.com";
            platforms = supportedSystems;
            mainProgram = "scour";
          };
        };
    in {
      packages = forAllSystems (system:
        let
          pkgs = import nixpkgs { inherit system; };
          pkg = mkSovereignPkg pkgs system;
        in {
          default = pkg;
          "scour" = pkg;
        }
      );

      apps = forAllSystems (system: {
        default = {
          type = "app";
          program = "${self.packages.${system}.default}/bin/scour";
        };
      });

      overlays.default = final: prev: {
        "scour" = mkSovereignPkg final final.stdenv.hostPlatform.system;
      };

      nixosModules.scour = { config, lib, pkgs, ... }:
        let
          cfg = config.services.scour;
        in {
          options.services.scour = {
            enable = lib.mkEnableOption "Scour Sovereign Service";
            package = lib.mkOption {
              type = lib.types.package;
              default = self.packages.${pkgs.stdenv.hostPlatform.system}.default;
              description = "Package providing scour.";
            };
          };
          config = lib.mkIf cfg.enable {
            environment.systemPackages = [ cfg.package ];
          };
        };
    };
}
