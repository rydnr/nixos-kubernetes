{ config, lib, pkgs, ... }:

let
  # Define a function to generate the CA certificate
  generateCaCert = pkgs.writeScriptBin "generate-ca-cert" ''
    #!/usr/bin/env bash
    set -e
    CA_FILE="${1}"
    DAYS="${2}"
    CN="${3}"
    openssl req -x509 -newkey rsa:4096 -keyout "$CA_FILE.key" -out "$CA_FILE" -days $DAYS -nodes -subj "/CN=$CN"
  '';

in
{
  options.services.raw-kubernetes-ca = {
    enable = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = "Enable the Kubernetes CA service.";
    };
    caFile = lib.mkOption {
      type = lib.types.nullOr lib.types.path;
      default = null;
      description = "Path to the CA file. If not provided, one will be generated.";
    };
    caName = lib.mkOption {
      type = lib.types.str;
      default = null;
      description = "The name used to identify the certificate authority.";
    };
    caCommonName = lib.mkOption {
      type = lib.types.str;
      default = null;
      description = "The common name of the certificate authority.";
    };
    caExpirationDays = lib.mkOption {
      type = lib.types.nullOr lib.types.int;
      default = 365;
      description = "The number of days until the certificate authority expires.";
    };
  };

  config = lib.mkIf config.services.raw-kubernetes-ca.enable {
    systemd.services.raw-kubernetes-ca = {
      description = "Manages the certificate authority used by Kubernetes";
      svcManager = "command";
      wantedBy = [ "multi-user.target" ];

      serviceConfig = {
        ExecStart = ''
          ${if config.services.raw-kubernetes-ca.caFile == null then
            "${generateCaCert} /etc/ssl/certs/${config.services.raw-kubernetes-ca.caName}.pem ${config.services.raw-kubernetes-ca.caExpirationDays} ${config.services.raw-kubernetes-ca.caCommonName}"
          else
            "echo 'Using ${config.services.raw-kubernetes-ca.caFile} as certificate authority for Kubernetes'"
          }
        '';
      };

      # Ensure the service runs only once
      Type = "oneshot";
      RemainAfterExit = true;
    };

    # Expose the CA file path
    systemd.services.raw-kubernetes-ca.path = [ pkgs.openssl ];

    environment.etc."ssl/certs/${config.services.raw-kubernetes-ca.caName}.pem".source = if config.services.raw-kubernetes-ca.caFile == null then
      "/etc/ssl/certs/${config.services.raw-kubernetes-ca.caName}.pem"
    else
      config.services.raw-kubernetes-ca.caFile;
  };
}
