{
  description = "Rapidly Search and Hunt through Windows Forensic Artefacts";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";

  outputs = inputs: let
    systems = ["x86_64-linux"];
    genSystems = inputs.nixpkgs.lib.genAttrs systems;
  in {
    devShells = genSystems (system: let
      pkgs = inputs.nixpkgs.legacyPackages.${system};
    in {
      default = pkgs.mkShell {
        inputsFrom = [inputs.self.packages.${system}.chainsaw];
        packages = with pkgs; [
          cargo
          pre-commit
          rust-analyzer
          rustc
          rustfmt
          vscode-extensions.llvm-org.lldb-vscode
          inputs.self.packages.${system}.chainsaw
        ];

        RUST_SRC_PATH = pkgs.rustPlatform.rustLibSrc;
      };
    });

    packages = genSystems (system: let
      pkgs = inputs.nixpkgs.legacyPackages.${system};

    in {
      chainsaw = pkgs.rustPlatform.buildRustPackage {
        pname = "chainsaw";
        version = "2.11.0";

        src = ./.;

        doCheck = false;

        cargoLock.lockFile = ./Cargo.lock;
      };
      default = inputs.self.packages.${system}.chainsaw;
    });

    formatter = genSystems (system: inputs.nixpkgs.legacyPackages.${system}.alejandra);
  };
}
