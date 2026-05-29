{
  description = "canon-megatank-reset — Linux fleet Canon MegaTank waste-ink reset + protocol RE";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs =
    { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
        corePackages = with pkgs; [
          # Python: base interpreter; uv manages the venv + deps from pyproject.toml
          # (keeps the devShell lean + cache-friendly — no per-package nix builds).
          python312
          uv
          ruff
          mypy

          # Build orchestration / SSOT
          just
          git
          git-filter-repo
          gh
          jq
          gitleaks
          git-cliff

          # Secrets / fleet
          sops
          age
          ansible
          ansible-lint
          yamllint

          # USB protocol RE (host-side capture lives on mbp-13 via the
          # canon_tool_dev ansible role; these are the analysis-side tools)
          wireshark-cli   # tshark — pcap analysis (pcap.py shells to it)
        ];
      in
      {
        devShells.default = pkgs.mkShell {
          buildInputs = corePackages;
          shellHook = ''
            echo "canon-megatank-reset devshell — 'just --list' for recipes"
          '';
        };
      }
    );
}
