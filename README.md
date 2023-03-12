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

- key
	- generate: generate a random keypair
	- inspect: inspect private keys
	- verify: verify signatures

- ln
	- invoice
		- decode: decode Lightning invoices

- message
    - hash: get hashes of Bitcoin Signed Message
    - sign: sign a message using Bitcoin Signed Message
    - verify: verify a Bitcoin Signed Message
    - recover: recover the pubkey or address that signed a message

- psbt
	- create: create a PSBT from a raw unsigned transaction
	- decode: decode a PSBT to JSON
	- edit: edit a PSBT inline
	- finalize: finalize a PSBT into a fully signed transaction
	- merge: merge multiple PSBTs into one

- script
	- decode: decode a PSBT to JSON
	- coming soon: script descriptor support

- tx
	- create: create a binary transaction from JSON
	- decode: decode a binary transaction to JSON


## Minimum Supported Rust Version (MSRV)

`hal` should always compile on **Rust 1.41.1**.
Note that it should be build using the `Cargo.lock` file, so using `--locked`.

# Extensions

hal allows the use of extensions that can be installed separately.

## Known extensions:

- [hal-elements](https://github.com/stevenroose/hal-elements/): support for Elements sidechains like Liquid


## Ideas:
- optional [Trezor](https://github.com/stevenroose/rust-trezor-api/) and Ledger integration
