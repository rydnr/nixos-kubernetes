# flake.nix
#
# This file packages NixOS modules for Kubernetes as a Nix flake.
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
  description = "Defines NixOS modules for Kubernetes";

  inputs = rec {
    nixpkgs.url = "github:NixOS/nixpkgs/24.05";
    flake-utils.url = "github:numtide/flake-utils/v1.0.0";
    cert = {
      url = "github:rydnr/nixos-cert-functions";
      inputs.nixos.follows = "nixpkgs";
    };
  };

  outputs = inputs:
    with inputs;
    flake-utils.lib.eachDefaultSystem
    (system: {
      nixosModules = {
        raw-kubernetes-ca = ./kubernetes-ca.nix;
        raw-kube-apiserver = { config, pkgs, lib, ... }: import ./kube-apiserver.nix { inherit config pkgs lib; mkCert = cert.outputs.lib.mkCert; };
        raw-kube-scheduler = ./kube-scheduler.nix;
        raw-kube-controller-manager = ./kube-controller-manager.nix;
        raw-kube-proxy = { config, pkgs, lib, ... }: import ./kube-proxy.nix {inherit config pkgs lib nixpkgs;};
        raw-kubelet = ./kubelet.nix;
      };
    });
}

#    outputs = { self, nixos, flake-utils }: {
#    nixosModules = { kubeApiserver = ./kube-apiserver.nix; };
#};
