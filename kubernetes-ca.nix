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
    #!/usr/bin/env ${pkgs.bash}/bin/bash
    set -e
    CA_NAME="$1";
    DAYS="$2";
    SSL_FOLDER="$3";
    C="$4";
    ST="$5";
    L="$6";
    O="$7";
    OU="$8";
    CN="$9";
    ${pkgs.openssl}/bin/openssl req -x509 -newkey rsa:4096 -keyout "$SSL_FOLDER/$CA_NAME.key" -out "$SSL_FOLDER/$CA_NAME.pem" -days $DAYS -nodes -subj "/C=$C/ST=$ST/L=$L/O=$O/OU=$OU/CN=$CN"
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
    caExpirationDays = lib.mkOption {
      type = lib.types.nullOr lib.types.int;
      default = 365;
      description = "The number of days until the certificate authority expires.";
    };
    caCountry = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      description = "The two-letter ISO code for the country where the organization of the certificate authority is located.";
    };
    caState = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      description = "The full name of the state or province where the organization of the certificate authority is located.";
    };
    caLocality = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      description = "The city or locality where the organization of the certificate authority is located.";
    };
    caOrganization = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      description = "The legal name of the organization of the certificate authority.";
    };
    caOrganizationalUnit = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      description = "The organizational unit (division of the organization in charge) of the certificate authority.";
    };
    caCommonName = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      description = "The name of the individual or organization of the certificate authority.";
    };
  };

  config = mkIf cfg.enable {
    systemd.services.raw-kubernetes-ca = {
      inherit description;
      wantedBy = [ "multi-user.target" ];

      serviceConfig = {
        ExecStart = ''
          ${if cfg.caFile == null then "${generateCaCert}/bin/generate-ca-cert '${cfg.caName}' '${toString cfg.caExpirationDays}' '${cfg.sslFolder}' '${cfg.caCountry}' '${cfg.caState}' '${cfg.caLocality}' '${cfg.caOrganization}' '${cfg.caOrganizationalUnit}' '${cfg.caCommonName}'"
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
