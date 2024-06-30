{
  config,
  pkgs,
  lib,
  ...
}:

with lib;

let
  cfg = config.services.raw-kubernetes-ca;
  description = "an utility to manage the Kubernetes certificate authority";
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

    KEY="$CA_DIRECTORY/private/$CA_NAME.key"
    CRT="$CA_DIRECTORY/certs/$CA_NAME.crt"
    IDX="$CA_DIRECTORY/$CA_NAME-index.txt"
    SRL="$CA_DIRECTORY/$CA_NAME-serial"
    CRLDIR="$CA_DIRECTORY/crl"
    CRL="$CRLDIR/$CA_NAME-crl.pem"
    CRLN="$CA_DIRECTORY/$CA_NAME-crlnumber"

    # Initialize database files
    [[ -f "$IDX" ]] || command touch "$IDX"
    [[ -f "$SRL" ]] || command echo 1000 > "$SRL"

    [[ -d "$CRLDIR" ]] || command mkdir "$CRLDIR"
    [[ -f "$CRLN" ]] || command echo 01 > "$CRLN"

    # Generate the private key
    [[ -f "$KEY" ]] || ${pkgs.openssl}/bin/openssl genpkey -algorithm RSA -aes256 -out "$KEY" -pass pass:"$CA_PASSWORD" -pkeyopt rsa_keygen_bits:4096

    # Use the private key to create a self-signed x509 certificate for the certificate authority.
    [[ -f "$CRT" ]] || ${pkgs.openssl}/bin/openssl req -new -x509 -key "$KEY" -sha256 -passin pass:"$CA_PASSWORD" -out "$CRT" -days "$DAYS" -subj "/C=$C/ST=$ST/L=$L/O=$O/OU=$OU/CN=$CN"

    # Generate a CRL if it doesn't exist
    [[ -f "$CRL" ]] || ${pkgs.openssl}/bin/openssl ca -gencrl -crldays "$DAYS" -out "$CRL" -passin pass:"$CA_PASSWORD" -config /etc/openssl.cnf
  '';
in
{
  options.services.raw-kubernetes-ca = {
    enable = lib.mkOption {
      type = lib.types.bool;
      default = false;
      inherit description;
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
    environment.systemPackages = with pkgs; [ bash coreutils openssl ];
    environment.etc = mkIf (!builtins.pathExists "/etc/openssl.cnf") {
      "openssl.cnf".text = ''
[ ca ]
default_ca = ${cfg.caName}_ca

[ ${cfg.caName}_ca ]
dir = ${cfg.caDirectory}
certs = $dir/certs
crl_dir = $dir/crl
new_certs_dir = $dir/newcerts
database = $dir/${cfg.caName}-index.txt
serial = $dir/${cfg.caName}-serial
private_key = $dir/private/${cfg.caName}.key
certificate = $dir/certs/${cfg.caName}.crt
crlnumber = $dir/${cfg.caName}-crlnumber
crl = $crl_dir/${cfg.caName}-crl.pem
RANDFILE = $dir/private/.rand
default_md = sha256
string_mask = utf8only

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
commonName_max = 64

[ v3_ca ]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = critical, CA:true
keyUsage = critical, digitalSignature, cRLSign, keyCertSign
'';
    };

    systemd.services.raw-kubernetes-ca = {
      inherit description;
      after = [ "network.target" ];
      wantedBy = [ "multi-user.target" ];

      serviceConfig = {
        Type = "oneshot";
        ExecStart = ''
          ${if cfg.caCrtFile == null then "${generateCaCert}/bin/generate-ca-cert '${cfg.caName}' '${cfg.caPassword}' '${toString cfg.caExpirationDays}' '${cfg.caDirectory}' '${cfg.caCountry}' '${cfg.caState}' '${cfg.caLocality}' '${cfg.caOrganization}' '${cfg.caOrganizationalUnit}' '${cfg.caCommonName}'"
          else
            "echo 'Using ${cfg.caCrtFile} as certificate authority for Kubernetes'"
          }
        '';
        ExecStartPre = [
          # Ensure proper permissions
          ''${pkgs.coreutils}/bin/install -d -m 0700 -o root -g root ${cfg.caDirectory}/private''
          ''${pkgs.coreutils}/bin/install -d -m 0755 -o root -g root ${cfg.caDirectory}/certs''
          ''${pkgs.coreutils}/bin/install -d -m 0755 -o root -g root ${cfg.caDirectory}/crl''
          ''${pkgs.coreutils}/bin/install -d -m 0755 -o root -g root ${cfg.caDirectory}/newcerts''
        ];
      };
    };
  };
}
