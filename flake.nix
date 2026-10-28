{
  description = "Xray subscription tester: test share links, report working ones";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
        tester = pkgs.python3.pkgs.buildPythonApplication {
          pname = "proxenith";
          version = "0.1.0";
          license = pkgs.lib.licenses.wtfpl;
          format = "other";
          src = ./.;
          propagatedBuildInputs = with pkgs.python3Packages; [ pyyaml ];
          installPhase = ''
            mkdir -p $out/bin
            install -m755 tester.py $out/bin/proxenith
            wrapProgram $out/bin/proxenith \
              --prefix PATH : ${pkgs.lib.makeBinPath [ pkgs.xray pkgs.curl ]}
          '';
        };
      in
      {
        packages.default = tester;

        packages.webui = pkgs.stdenv.mkDerivation {
          pname = "proxenith-webui";
          license = pkgs.lib.licenses.wtfpl;
          version = "0.1.0";
          src = ./.;
          nativeBuildInputs = [ pkgs.makeWrapper ];
          installPhase = ''
            mkdir -p $out/lib $out/bin
            install tester.py webui.py $out/lib/
            makeWrapper ${pkgs.python3.withPackages (ps: [ ps.pyyaml ])}/bin/python3 $out/bin/proxenith-webui \
              --add-flags "$out/lib/webui.py" \
              --prefix PATH : ${pkgs.lib.makeBinPath [ tester ]}
          '';
        };

        packages.chain-runner = pkgs.writeShellScriptBin "proxenith-chain-runner" ''
          export PATH=${tester}/bin:${pkgs.xray}/bin:$PATH
          exec ${pkgs.python3.withPackages (ps: [ ps.pyyaml ])}/bin/python3 \
            ${./chain-runner.py} "$@"
        '';

        devShells.default = pkgs.mkShell {
          packages = with pkgs; [ python3 python3Packages.pyyaml xray curl ];
        };
      })
    // {
      # Systemd example — install the package, then wire the timer:
      #   systemd.user.services.proxenith = {
      #     Unit.Description = "Test xray subscriptions";
      #     Service.ExecStart = "${pkg}/bin/proxenith /path/to/config.yaml";
      #   };
      #   systemd.user.timers.proxenith = {
      #     Unit.Description = "Run xray subscription tester every 6h";
      #     Timer.OnCalendar = "0/6:00:00";
      #     Timer.Persistent = true;
      #     Install.WantedBy = [ "timers.target" ];
      #   };
      overlays.default = final: prev: { proxenith = self.packages.${prev.system}.default; };
    };
}
