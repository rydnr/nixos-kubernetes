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
    CA_PASSWORD="$2";
    DAYS="$3";
    CA_DIRECTORY="$4";
    C="$5";
    ST="$6";
    L="$7";
    O="$8";
    OU="$9";
    CN="$10";

    # Generate the private key
    ${pkgs.openssl}/bin/openssl genpkey -algorithm RSA -aes256 -out "$CA_DIRECTORY/private/$CA_NAME.key" -pass pass:"$CA_PASSWORD" -pkeyopt rsa_keygen_bits:4096

    # Use the private key to create a self-signed x509 certificate for the certificate authority.
    ${pkgs.openssl}/bin/openssl req -new -x509 -key "$CA_DIRECTORY/private/$CA_NAME.key" -sha256 -passin pass:"$CA_PASSWORD" -out "$CA_DIRECTORY/certs/$CA_NAME.crt" -days $DAYS -nodes -subj "/C=$C/ST=$ST/L=$L/O=$O/OU=$OU/CN=$CN"

    # Initialize database files
    touch ${cfg.caDirectory}/index.txt
    echo 1000 > ${cfg.caDirectory}/serial
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
    caDirectory = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = "/etc/ssl/ca";
      description = "The base folder for certificate authorities.";
    };
    caName = lib.mkOption {
      type = lib.types.str;
      default = null;
      description = "The name used to identify the certificate authority.";
    };
    caPassword = lib.mkOption {
      type = lib.types.str;
      default = null;
      description = "Password for the certificate authority.";
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
      after = [ "network.target" ];
      wantedBy = [ "multi-user.target" ];

      environment.systemPackages = [ pkgs.openssl ];

      serviceConfig = {
        Type = "oneshot";
        ExecStart = ''
          ${if cfg.caFile == null then "${generateCaCert}/bin/generate-ca-cert '${cfg.caName}' '${cfg.caPassword}' '${toString cfg.caExpirationDays}' '${cfg.caDirectory}' '${cfg.caCountry}' '${cfg.caState}' '${cfg.caLocality}' '${cfg.caOrganization}' '${cfg.caOrganizationalUnit}' '${cfg.caCommonName}'"
          else
            "echo 'Using ${cfg.caFile} as certificate authority for Kubernetes'"
          }
        '';
        ExecStartPre = [
          # Ensure proper permissions
          ''install -d -m 0700 -o root -g root ${cfg.caDirectory}/private''
          ''install -d -m 0755 -o root -g root ${cfg.caDirectory}/certs''
          ''install -d -m 0755 -o root -g root ${cfg.caDirectory}/crl''
          ''install -d -m 0755 -o root -g root ${cfg.caDirectory}/newcerts''
        ];
      };

      environment.etc."openssl.cnf" = ''
      [ ca ]
      default_ca = CA_default

      [ CA_default ]
      dir = ${cfg.caDirectory}
      certs = $dir/certs
      crl_dir = $dir/crl
      new_certs_dir = $dir/newcerts
      database = $dir/index.txt
      serial = $dir/serial
      private_key = $dir/private/ca.key
      certificate = $dir/certs/ca.crt
      crlnumber = $dir/crlnumber
      crl = $dir/crl.pem
      RANDFILE = $dir/private/.rand

      [ req ]
      default_bits = 2048
      distinguished_name = req_distinguished_name
      string_mask = utf8only
      default_md = sha256

      [ req_distinguished_name ]
      countryName = ${cfg.caCountry}
      countryName_default = ES
      stateOrProvinceName = ${cfg.caState}
      stateOrProvinceName_default = Madrid
      localityName = ${cfg.caLocality}
      localityName_default = Madrid
      organization = ${cfg.caOrganization}
      organization_default = example
      organizationalUnitName = ${cfg.caOrganizationalUnit}
      organizationalUnitName_default = IT
      commonName = ${cfg.caCommonName}
      commonName_default = example.com
    '';
    };
  };
}
