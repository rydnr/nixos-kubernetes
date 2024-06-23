{
  config,
  pkgs,
  lib,
  ...
}:

with lib;

let
  cfg = config.services.raw-kubernetes-ca;
  description = "Manages the certificate authority used by Kubernetes";
  generateCaCert = pkgs.writeScriptBin "generate-ca-cert" ''
    #!/usr/bin/env /bin/sh
    set -e
    CA_NAME="$1";
    DAYS="$2";
    CN="$3";
    SSL_FOLDER="$4";
    openssl req -x509 -newkey rsa:4096 -keyout "$SSL_FOLDER/$CA_NAME.key" -out "$SSL_FOLDER/$CA_NAME.pem" -days $DAYS -nodes -subj "/CN=$CN"
  '';
in
{
  options.services.raw-kubernetes-ca = {
    enable = lib.mkOption {
      type = lib.types.bool;
      default = false;
      inherit description;
    };
    caFile = lib.mkOption {
      type = lib.types.nullOr lib.types.path;
      default = null;
      description = "Path to the CA file. If not provided, one will be generated.";
    };
    sslFolder = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = "/etc/ssl/certs";
      description = "The base folder for SSL files.";
    };
    caName = lib.mkOption {
      type = lib.types.str;
      default = null;
      description = "The name used to identify the certificate authority.";
    };
    caCommonName = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      description = "The common name of the certificate authority.";
    };
    caExpirationDays = lib.mkOption {
      type = lib.types.nullOr lib.types.int;
      default = 365;
      description = "The number of days until the certificate authority expires.";
    };
  };

  config = mkIf cfg.enable {
    systemd.services.raw-kubernetes-ca = {
      inherit description;
      wantedBy = [ "multi-user.target" ];

      serviceConfig = {
        ExecStart = ''
          ${if cfg.caFile == null then "${generateCaCert}/bin/generate-ca-cert ${cfg.caName} ${toString cfg.caExpirationDays} ${cfg.caCommonName} ${cfg.sslFolder}"
          else
            "echo 'Using ${cfg.caFile} as certificate authority for Kubernetes'"
          }
        '';
      };
    };

    environment.etc."${cfg.sslFolder}/${cfg.caName}.pem".source = if cfg.caFile == null then
      "${cfg.sslFolder}/${cfg.caName}.pem"
    else
      cfg.caFile;
  };
}
