CHANGELOG
=========

# v0.6.1  --  2020/04/16

- Support `tx/block create` reading JSON from stdin.
- Warn earlier when conflicting addresses are used in `tx create`.
- Improve description on `tx/block create` commands.

# v0.6.0  --  2020/03/24

- Don't print newlines after output.
- Update `quote` dependency.
- Use `base64-compat` crate instead of `base64`.

# v0.5.4  --  2020/02/25

- Fix compressedness bug in `hal message verify`.

# v0.5.3  --  2020/02/19

- Add `hal message hash` command.

# v0.5.2  --  2020/01/24

- Small fix in `hal message recover` and compressedness.

# v0.5.1  --  2020/01/24

- Add `hal message recover`.
- Fix `hal message sign`.

# v0.5.0  --  2020/01/10

- Renamed `address-*` fields in bip32 info to single `addresses` object.
- Remove `compressed_public_key` field from key info.
- Add signature and pubkey info to lightnig invoice.
- Add support for Bitcoin Signed Message
- Update `bitcoin` dependency to v0.23.0.

# v0.4.4  --  2019/10/01

- add `hal key verify` command for signature verification

# v0.4.3  --  2019/09/23

- make compatible with Rust v1.32.0

# v0.4.2  --  2019/09/23

- add bip39 support

# v0.3.0  --  2019/07/26

- add bech32 command tree
- add key inspect command
- add bip32 inspect command
- print a newline after output

# v0.2.0

- Update rust-bitcoin dependency v0.18.0

# v0.1.2

- Added utility methods to `HexBytes`

# v0.1.1

- Added `block decode` and `block create` commands.
- Added better description for `tx create`.

# v0.1.0

First version. Commands provided:
- address
	- inspect
	- create
- bip32
	- derive
- ln
	- invoice
		- decode
- psbt
	- create
	- decode
	- edit
	- finalize
	- merge
- script
	- decode
- tx
	- create
	- decode

