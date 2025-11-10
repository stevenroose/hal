{
	description = "ark";

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
				rustVersion = "1.74.0";

				isDarwin = pkgs.stdenv.hostPlatform.isDarwin;
				overlays = [ rust-overlay.overlays.default ];
				pkgs = import nixpkgs {
					inherit system overlays;
				};

				rust = pkgs.rust-bin.stable.${rustVersion}.default.override {
					extensions = [ "rust-src" ]; #"rust-analyzer" ];
				};

			in
			{
				devShells.default = pkgs.mkShell {
					nativeBuildInput = [ ];
					buildInputs = [
						rust
						pkgs.llvmPackages.clang
						pkgs.pkg-config
					];

					LIBCLANG_PATH = "${pkgs.llvmPackages.clang-unwrapped.lib}/lib/";
				};
			}
		);
}
