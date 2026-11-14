# ffp: FFP-SCOUR-MINER-NIX declarative nix
{ config, lib, pkgs, ... }:
let
  cfg = config.services.tx-scour-miner;
in {
  options.services.tx-scour-miner = {
    enable = lib.mkEnableOption "TianxiaOS Scour, Tyrawn & SFI Opportunity Miner Organism";
    dataDir = lib.mkOption {
      type = lib.types.str;
      default = "/var/lib/tianxia-scour-miner";
      description = "Isolated state directory for MERGED_SIGNALS.jsonl and SFI reports.";
    };
  };

  config = lib.mkIf cfg.enable {
    systemd.services.tx-scour-miner = {
      description = "TianxiaOS Autonomous Signal Harvester & Opportunity Miner";
      serviceConfig = {
        Type = "oneshot";
        Environment = [ "TX_BASE_DIR=${cfg.dataDir}" ];
        ExecStart = "${pkgs.python3}/bin/python3 ${../src/tx_scour.py} digest --limit 25";
        NoNewPrivileges = true;
        ProtectSystem = "strict";
        ReadWritePaths = [ cfg.dataDir ];
        MemoryMax = "512M";
        TasksMax = 32;
      };
    };
  };
}
