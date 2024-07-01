{
  config,
  pkgs,
  lib,
  ...
}:

with lib;

let
  cfg = config.services.raw-kube-proxy-certificate;
  description = "an utility to manage the kube-proxy certificate";
  generateCert = pkgs.writeScriptBin "generate-cert" ''
    #!/usr/bin/env ${pkgs.bash}/bin/bash
    set -e
    CERT_NAME="$1";
    CERT_PASSWORD="$2";
    DAYS="$3";
    CERT_DIRECTORY="$4";
    CA_CRT="$5";
    CA_KEY="$6";
    CA_PASSWORD="$7";
    C="$8";
    ST="$9";
    L="$10";
    O="$11";
    OU="$12";
    CN="$13";
  
    KEY="$CERT_DIRECTORY/private/$CERT_NAME.key"
    CSR="$CERT_DIRECTORY/csr/$CERT_NAME.csr"
    CRT="$CERT_DIRECTORY/certs/$CERT_NAME.crt"
  
    # Generate the private key
    [[ -f "$KEY" ]] || ${pkgs.openssl}/bin/openssl genpkey -algorithm RSA -aes256 -out "$KEY" -pass pass:"$CERT_PASSWORD" -pkeyopt rsa_keygen_bits:4096
  
    # Use the private key to create a certificate request for the certificate authority.
    [[ -f "$CSR" ]] || ${pkgs.openssl}/bin/openssl req -new -key "$KEY" -sha256 -passin pass:"$CERT_PASSWORD" -out "$CSR" -days "$DAYS" -subj "/C=$C/ST=$ST/L=$L/O=$O/OU=$OU/CN=$CN"
  
    # Sign the request with the certificate authority
    [[ -f "$CRT" ]] || ${pkgs.openssl}/bin/openssl x509 -req -in "$CSR" -CA "$CA_CRT" -CAkey "$CA_KEY" -out "$CRT" -days "$DAYS" -sha256 -passin pass:"$CA_PASSWORD"
  '';
in
{
  options.services.raw-kube-proxy-certificate = {
    enable = lib.mkOption {
      type = lib.types.bool;
      default = false;
      inherit description;
    };
    certName = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = "raw-kube-proxy";
      description = "The name of the certificate.";
    };
    certCrtFile = lib.mkOption {
      type = lib.types.nullOr lib.types.path;
      default = null;
      description = "Path to the certificate.";
    };
    caCrtFile = lib.mkOption {
      type = lib.types.nullOr lib.types.path;
      default = null;
      description = "Path to the CA file.";
    };
    caKeyFile = lib.mkOption {
      type = lib.types.nullOr lib.types.path;
      default = null;
      description = "Path to the CA key file.";
    };
    caPassword = lib.mkOption {
      type = lib.types.str;
      default = null;
      description = "Password for the certificate authority.";
    };
    certDirectory = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = "/etc/ssl";
      description = "The root directory tree where certificate should be stored.";
    };
    certPassword = lib.mkOption {
      type = lib.types.str;
      default = null;
      description = "Password for the certificate.";
    };
    certExpirationDays = lib.mkOption {
      type = lib.types.nullOr lib.types.int;
      default = 365;
      description = "The number of days until the certificate expires.";
    };
    certCountry = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      description = "The two-letter ISO code for the country where the organization of the certificate is located.";
    };
    certState = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      description = "The full name of the state or province where the organization of the certificate is located.";
    };
    certLocality = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      description = "The city or locality where the organization of the certificate is located.";
    };
    certOrganization = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      description = "The legal name of the organization of the certificate.";
    };
    certOrganizationalUnit = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      description = "The organizational unit (division of the organization in charge) of the certificate.";
    };
    certCommonName = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      description = "The name of the individual or organization of the certificate.";
    };
  };

  config = mkIf cfg.enable {
    environment.systemPackages = with pkgs; [ bash coreutils openssl ];

    systemd.services.raw-kube-proxy-certificate = {
      inherit description;
      after = [ "network.target" ];
      wantedBy = [ "multi-user.target" ];

      serviceConfig = {
        Type = "oneshot";
        ExecStart = ''
          ${if cfg.certCrtFile == null then "${generateCert}/bin/generate-cert '${cfg.certName}' '${cfg.certPassword}' '${toString cfg.certExpirationDays}' '${cfg.certDirectory}' '${cfg.caCrtFile}' '${cfg.caKeyFile}' '${cfg.caPassword}' '${cfg.certCountry}' '${cfg.certState}' '${cfg.certLocality}' '${cfg.certOrganization}' '${cfg.certOrganizationalUnit}' '${cfg.certCommonName}'"
          else
            "echo 'Using ${cfg.certFile} as certificate for kube-proxy'"
          }
        '';
        ExecStartPre = [
          # Ensure proper permissions
          ''${pkgs.coreutils}/bin/install -d -m 0755 -o root -g root ${cfg.certDirectory}/certs''
          ''${pkgs.coreutils}/bin/install -d -m 0755 -o root -g root ${cfg.certDirectory}/csr''
          ''${pkgs.coreutils}/bin/install -d -m 0700 -o root -g root ${cfg.certDirectory}/private''
        ];
      };
    };
  };
}
