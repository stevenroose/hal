hal -- the Bitcoin companion
============================

hal is a command line tool that provides all kinds of Bitcoin-related utilities.


# Installation

```
$ cargo install --locked hal
```


# Summary of commands:

- address
	- inspect: get information about addresses
	- create: create addresses using public keys or scripts

- bech32
	- decode: parse the elements of the Bech32 format
	- encode: encode data in the Bech32 format

- bip32
	- derive: derive keys and addresses from extended keys
	- inspect: inspect a BIP-32 xpub or xpriv

- bip39
    - generate: generate a new BIP-39 mnemonic
	- get-seed: get the seed value and BIP-32 master key for a given BIP-39 mnemonic

- block
	- create: create a binary block from JSON
	- decode: decode a binary block to JSON

- hash
	- sha256: hash data with SHA-256
	- sha256d: hash data with double SHA-256

- key
	- generate: generate a random keypair
	- derive: generate a public key from a private key
	- inspect: inspect private keys
	- ecdsa-sign: make ECDSA signatures
	- ecdsa-verify: verify ECDSA signatures
	- pubkey-tweak-add: add a scalar to a point
	- pubkey-combine: add two points together

- ln
	- invoice
		- decode: decode Lightning invoices

- merkle
    - proof-create: create a merkle proof
    - proof-check: check a merkle proof

- message
    - hash: get hashes of Bitcoin Signed Message
    - sign: sign a message using Bitcoin Signed Message
    - verify: verify a Bitcoin Signed Message
    - recover: recover the pubkey or address that signed a message

- miniscript
    - descriptor: get information about an output descriptor
    - instpect: inspect miniscripts
    - parse: parse a script into a miniscript
    - policy: inspect policies

- psbt
	- create: create a PSBT from a raw unsigned transaction
	- decode: decode a PSBT to JSON
	- edit: edit a PSBT inline
	- finalize: finalize a PSBT into a fully signed transaction
	- merge: merge multiple PSBTs into one

- random
    - bytes: generate random bytes

- script
	- decode: decode a PSBT to JSON

- tx
	- create: create a binary transaction from JSON
	- decode: decode a binary transaction to JSON


## Minimum Supported Rust Version (MSRV)

`hal` should always compile on **Rust 1.74.0**.
Note that it should be build using the `Cargo.lock` file, so using `--locked`.

# Extensions

hal allows the use of extensions that can be installed separately.

## Known extensions:

- [hal-elements](https://github.com/stevenroose/hal-elements/): support for Elements sidechains like Liquid


## Ideas:
- optional [Trezor](https://github.com/stevenroose/rust-trezor-api/) and Ledger integration
