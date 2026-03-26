{
  description = "python env";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
  };

  outputs = { self, nixpkgs, ... }:
    let
      system = "x86_64-linux"; # Change to "aarch64-darwin" for Apple Silicon
      pkgs = nixpkgs.legacyPackages.${system};
    in
    {
      devShells.${system}.default = pkgs.mkShell {
        name = "python-dev-env";

        # Packages available in the shell
        nativeBuildInputs = with pkgs; [
          # Python and core library
          (python3.withPackages (ps: with ps; [
            pip
            numpy
          ]))
          python3Packages.python-lsp-server
          stdenv.cc.cc.lib
          zlib
        ];

        shellHook = ''
          export LD_LIBRARY_PATH="${pkgs.lib.makeLibraryPath [ pkgs.stdenv.cc.cc.lib ]}:''${LD_LIBRARY_PATH}"
          
          echo "-------------------------------------------------------"
          echo "Python Dev Environment Active"
          echo "Python version: $(python --version)"
          echo "-------------------------------------------------------"
        '';
      };
    };
}