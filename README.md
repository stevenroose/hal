hal -- the Bitcoin companion
============================

hal is a command line tool that provides all kinds of Bitcoin-related utilities.


# Installation

```
$ cargo install hal
```


# Summary of commands:

- address
	- inspect: get information about addresses
	- create: create addresses using public keys or scripts

- bip32
	- derive: derive keys and addresses from extended keys

- ln
	- invoice
		- decode: decode Lightning invoices

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


# Extensions

hal allows the use of extensions that can be installed separately.

## Known extensions:

- [hal-elements](https://github.com/stevenroose/hal-elements/): support for Elements sidechains like Liquid


## Ideas:
- (extended) private key generation
- optional [Trezor](https://github.com/stevenroose/rust-trezor-api/) and Ledger integration
