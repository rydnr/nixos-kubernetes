{ config, pkgs, lib, ... }:

with lib;

let cfg = config.services.customService;
in {
  options.services.customService = {
    enable = mkOption {
      type = types.bool;
      default = false;
      description = "Enable custom service.";
    };
    exampleOption = mkOption {
      type = types.str;
      default = "defaultValue";
      description = "An example option for the custom service.";
    };
  };

  config = mkIf cfg.enable {
    systemd.services.customService = {
      description = "Custom Service";
      after = [ "network.target" ];
      wantedBy = [ "multi-user.target" ];

      serviceConfig = {
        ExecStart = "${pkgs.coreutils}/bin/echo ${cfg.exampleOption}";
      };

      install = { wantedBy = [ "multi-user.target" ]; };
    };
  };
}
