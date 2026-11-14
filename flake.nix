# ffp: FFP-SCOUR-MINER-FLAKE declarative nix
{
  description = "Scour v8.7.0 — Tier-3 Autonomous Signal Harvester (tx_scour + Tyrawn) & SFI Opportunity Miner";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.05";
    tianxia-core = {
      url = "github:Tianxia-Core/TianxiaOS";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, tianxia-core, ... }:
    let
      supportedSystems = [ "x86_64-linux" "aarch64-linux" ];
      forAllSystems = nixpkgs.lib.genAttrs supportedSystems;
    in {
      packages = forAllSystems (system:
        let
          pkgs = import nixpkgs { inherit system; };
          scourBin = pkgs.writeShellScriptBin "tx-scour" ''
            exec ${pkgs.python3}/bin/python3 ${./src/tx_scour.py} "$@"
          '';
          minerBin = pkgs.writeShellScriptBin "tx-opportunities-miner" ''
            exec ${pkgs.python3}/bin/python3 ${./src/tx_opportunities_miner.py} "$@"
          '';
        in {
          default = pkgs.symlinkJoin {
            name = "scour-8.7.0";
            paths = [ scourBin minerBin ];
          };
          tx-scour = scourBin;
          tx-opportunities-miner = minerBin;
        }
      );

      nixosModules = {
        default = ./nix/tx-scour-miner.nix;
        scour-miner = ./nix/tx-scour-miner.nix;
      };
    };
}
