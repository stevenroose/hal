{
	inputs = {
		nixpkgs.url = "nixpkgs/nixos-25.05";
		flake-utils.url = "github:numtide/flake-utils";
		fenix = {
			url = "github:nix-community/fenix";
			inputs.nixpkgs.follows = "nixpkgs";
		};
	};

	outputs = { self, nixpkgs, flake-utils, fenix }:
		flake-utils.lib.eachDefaultSystem (system:
			let
				pkgs = import nixpkgs {
					inherit system;
				};
				lib = pkgs.lib;

				rustVersion = "1.74.0";
				rustToolchain = fenix.packages.${system}.fromToolchainName {
					name = rustVersion;
					sha256 = "sha256-U2yfueFohJHjif7anmJB5vZbpP7G6bICH4ZsjtufRoU=";
				};
			in
			{
				devShells.default = pkgs.mkShell {
					packages = [
						rustToolchain.toolchain
						rustToolchain.rust-analyzer
						pkgs.git
						pkgs.llvmPackages.clang
					];

					LIBCLANG_PATH = "${pkgs.llvmPackages.clang-unwrapped.lib}/lib/";
					RUSTDOCS_STDLIB = "${rustToolchain.rust-docs}/share/doc/rust/html/std/index.html";
				};
			}
		);
}
