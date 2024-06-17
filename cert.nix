# flake.nix
#
# This file exports functions to create certificate authorities as a Nix flake.
#
# Copyright (C) 2024-today rydnr/nixos-kubernetes
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
{
  description = "Flake to create certificate authority files";
  inputs = rec {
    flake-utils.url = "github:numtide/flake-utils/v1.0.0";
    nixos.url = "github:NixOS/nixpkgs/24.05";
  };
  outputs = inputs:
    with inputs;
    let
      defaultSystems = flake-utils.lib.defaultSystems;
      supportedSystems = if builtins.elem "armv6l-linux" defaultSystems then
        defaultSystems
      else
        defaultSystems ++ [ "armv6l-linux" ];
    in flake-utils.lib.eachSystem supportedSystems (system:
      secret = { name, path }: "${path}/${name}.pem";
      caCert = path: secret "ca" path;
      mkCert = {
        name, CN, hosts ? [], fields ? {}, action ? "", privateKeyOwner, path }:
        rec {
          inherit name caCert CN hosts fields action path;
          cert = secret name path;
          key = secret "${name}-key" path;
          privateKeyOptions = {
            owner = privateKeyOwner;
            group = "nogroup";
            mode = "0600";
            path = key;
        };
      };

      in rec {
        functions = rec {
          inherit cacert mkCert secret;
          default = mkCert;
        };
      });
}
