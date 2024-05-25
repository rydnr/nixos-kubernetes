{
  config,
  pkgs,
  lib,
  ...
}:

with lib;

let
  cfg = config.services.customService;
in
{
  options.services.customService = {
    enable = mkOption {
      type = types.bool;
      default = false;
      description = "Enable custom service.";
    };

    # Generic flags
    advertiseAddress = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "The IP address on which to advertise the apiserver to members of the cluster. This address must be reachable by the rest of the cluster. If blank, the --bind-address will be used. If --bind-address is unspecified, the host's default interface will be used.";
    };
    cloudProviderGceL7lbSrcCidrs = mkOption {
      type = types.nullOr types.str;
      default = "130.211.0.0/22,35.191.0.0/16";
      description = "CIDRs opened in GCE firewall for L7 LB traffic proxy & health checks (default 130.211.0.0/22,35.191.0.0/16)";
    };
  };

  config = mkIf cfg.enable {
    systemd.services.customService = {
      description = "Custom Service";
      after = [ "network.target" ];
      wantedBy = [ "multi-user.target" ];

      serviceConfig = {
        ExecStart = ''
          ${pkgs.coreutils}/bin/echo ${pkgs.kubernetes}/bin/kube-apiserver \
            ${optionalString (cfg.advertiseAddress != null) "--advertise-address ${cfg.advertiseAddress}"} \
            ${
              optionalString (
                cfg.cloudProviderGceL7lbSrcCidrs != null
              ) "--cloud-provider-gce-l7lb-src-cidrs ${cfg.cloudProviderGceL7lbSrcCidrs}"
            }

        '';
      };
    };
  };
}
