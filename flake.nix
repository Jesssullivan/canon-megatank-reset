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
        # mermaid-cli (mmdc) renders via headless Chrome through puppeteer. nixpkgs
        # ships no bundled browser, and chromium is Linux-only — so wire it in only
        # where it builds (Linux: the CI target + the fleet box). On darwin the
        # `just diagrams` recipe falls back to `npx @mermaid-js/mermaid-cli`.
        mermaidBrowser = pkgs.lib.optional pkgs.stdenv.isLinux pkgs.chromium;
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

          # Documentation build (SSOT for `just paper` + `just diagrams`):
          # the IEEE paper and the diagram sources must build in-shell and in CI
          # without any ambient/global install. Pin them in the devShell.
          tectonic        # `just paper` — docs/paper/*.tex → PDF (one-shot LaTeX)
          mermaid-cli     # `just diagrams` — mmdc renders docs/diagrams/*.mmd
          graphviz        # `just diagrams` — dot renders docs/diagrams/*.dot
        ];
      in
      {
        devShells.default = pkgs.mkShell {
          buildInputs = corePackages ++ mermaidBrowser;
          shellHook = ''
            echo "canon-megatank-reset devshell — 'just --list' for recipes"
          ''
          # Point mermaid-cli/puppeteer at the nix-provided chromium (Linux only)
          # so `just diagrams` renders headlessly without an out-of-band download.
          + pkgs.lib.optionalString pkgs.stdenv.isLinux ''
            export PUPPETEER_EXECUTABLE_PATH="${pkgs.chromium}/bin/chromium"
            export PUPPETEER_SKIP_DOWNLOAD=1
          '';
        };
      }
    );
}
