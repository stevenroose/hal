{
	inputs = {
		nixpkgs.url = "nixpkgs/nixos-24.05";
		flake-utils = {
			url = "github:numtide/flake-utils";
		};
		rust-overlay = {
			url = "github:oxalica/rust-overlay";
			inputs.nixpkgs.follows = "nixpkgs";
		};
	};

	outputs = { self, nixpkgs, flake-utils, rust-overlay }:
		flake-utils.lib.eachDefaultSystem (system:
			let
				lib = nixpkgs.lib;
				overlays = [ rust-overlay.overlays.default ];
				target = lib.strings.replaceStrings [ "-" ] [ "_" ] pkgs.stdenv.buildPlatform.config;
				pkgs = import nixpkgs {
					inherit system overlays;
				};

				rustDefault = pkgs.rust-bin.stable."1.84.0".default.override {
					extensions = [ "rust-src" "rust-analyzer" ];
				};
				rustMsrv = pkgs.rust-bin.stable."1.56.1".default.override {
					extensions = [ "rust-src" ];
				};
			in
			{
				devShells.default = pkgs.mkShell {
					nativeBuildInput = [ ];
					buildInputs = [
						pkgs.git
						pkgs.llvmPackages.clang
						rustDefault
					];

					LIBCLANG_PATH = "${pkgs.llvmPackages.clang-unwrapped.lib}/lib/";
				};
				devShells.msrv = pkgs.mkShell {
					nativeBuildInput = [ ];
					buildInputs = [
						pkgs.git
						pkgs.llvmPackages.clang
						rustMsrv
					];

					LIBCLANG_PATH = "${pkgs.llvmPackages.clang-unwrapped.lib}/lib/";
				};
			}
		);
}
