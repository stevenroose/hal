//! Vanity address generation.
//!
//! The approach is taken from nakatoshi (https://github.com/ndelvalle/nakatoshi),
//! in particular https://github.com/ndelvalle/nakatoshi/pull/399.
//!
//! Instead of deriving every public key from a random secret key, a random
//! secret key is picked and the keys after it are walked in batches. Getting
//! from one public key to the next only takes adding G, and all the divisions
//! of a batch are replaced by a single one using Montgomery's trick. Prefixes
//! are matched against the public key hash (or Taproot output key) directly,
//! without creating an address for every key.

use std::convert::{TryFrom, TryInto};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};

use bitcoin::address::NetworkUnchecked;
use bitcoin::hashes::{hash160, Hash, HashEngine};
use bitcoin::key::TweakedPublicKey;
use bitcoin::secp256k1::{self, Scalar, SecretKey};
use bitcoin::taproot::TapTweakHash;
use bitcoin::{Address, CompressedPublicKey, Network, NetworkKind, PrivateKey, ScriptBuf};
use k256::{FieldBytes, FieldElement};
use serde::{Deserialize, Serialize};

use crate::key::KeyInfo;
use crate::SECP;

const BECH32_CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
// The number of characters that encode the 20 byte hash of a p2wpkh address.
const P2WPKH_DATA_LEN: usize = 32;
// The number of characters that encode the 32 byte output key of a p2tr address.
const P2TR_DATA_LEN: usize = 52;

const BASE58_CHARSET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
// Version byte, 20 byte hash and 4 byte checksum.
const BASE58_PAYLOAD_LEN: usize = 25;
const BASE58_MAX_ADDRESS_LEN: usize = 35;
// Above this many upper/lowercase variants of the prefixes, the slow matcher is used.
const BASE58_MAX_VARIANTS: usize = 1 << 16;

// A batch has a center key, and this many keys on both sides of it.
const HALF_BATCH_SIZE: usize = 1024;
const BATCH_SIZE: usize = 2 * HALF_BATCH_SIZE + 1;

// The tweak of a Taproot address is split up in windows of this many bits.
const TWEAK_WINDOW_BITS: usize = 13;
// The number of values a window can have.
const TWEAK_WINDOW_SIZE: usize = 1 << TWEAK_WINDOW_BITS;
const TWEAK_WINDOWS: usize = (256 + TWEAK_WINDOW_BITS - 1) / TWEAK_WINDOW_BITS;

/// The type of vanity address to generate.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum VanityAddressType {
	P2pkh,
	P2wpkh,
	P2tr,
}

impl VanityAddressType {
	pub fn as_str(&self) -> &'static str {
		match self {
			VanityAddressType::P2pkh => "p2pkh",
			VanityAddressType::P2wpkh => "p2wpkh",
			VanityAddressType::P2tr => "p2tr",
		}
	}
}

/// A vanity address that was found.
#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct VanityAddressInfo {
	pub address: Address<NetworkUnchecked>,
	/// The number of addresses that were tried before this one was found.
	pub attempts: u64,
	#[serde(flatten)]
	pub key: KeyInfo,
}

/// A vanity address that was found.
#[derive(Clone, Debug)]
pub struct VanityAddress {
	pub private_key: PrivateKey,
	pub address: Address,
	/// The number of addresses that were tried before this one was found.
	pub attempts: u64,
}

/// A search for addresses starting with one of a set of prefixes.
pub struct VanitySearch {
	prefixes: Vec<String>,
	case_sensitive: bool,
	compressed: bool,
	// For p2tr, use the public key as the output key, without tweaking it.
	raw_taproot: bool,
	address_type: VanityAddressType,
	network: Network,
	matcher: PrefixMatcher,
}

impl VanitySearch {
	/// Set up a search for addresses starting with any of the prefixes.
	///
	/// The type of address is derived from the prefixes, which have to start
	/// with what all the addresses of that type start with (like `1`, `bc1q` or
	/// `bc1p` on mainnet). Segwit addresses are always matched case
	/// insensitively, `compressed` can only be false for p2pkh.
	///
	/// If no network is given, it is derived from the prefixes as well.
	/// Prefixes for testnet are also valid for testnet4 and signet.
	pub fn new(
		prefixes: Vec<String>,
		case_sensitive: bool,
		compressed: bool,
		network: Option<Network>,
	) -> Result<VanitySearch, String> {
		if prefixes.is_empty() {
			return Err("no prefix given".to_owned());
		}
		let network = match network {
			Some(network) => network,
			None => {
				let mut network = None;
				for prefix in &prefixes {
					let net = network_for_prefix(prefix)?;
					if network.map(|n| n != net).unwrap_or(false) {
						return Err("all prefixes must be for the same network".to_owned());
					}
					network = Some(net);
				}
				network.unwrap()
			},
		};
		let mut address_type = None;
		for prefix in &prefixes {
			let tp = address_type_for_prefix(prefix, network)?;
			if address_type.map(|t| t != tp).unwrap_or(false) {
				return Err("all prefixes must be for the same type of address".to_owned());
			}
			address_type = Some(tp);
		}
		let address_type = address_type.unwrap();
		if !compressed && address_type != VanityAddressType::P2pkh {
			return Err(format!("{} addresses can only use compressed keys", address_type.as_str()));
		}
		// Segwit addresses are always lowercase.
		let case_sensitive = case_sensitive && address_type == VanityAddressType::P2pkh;

		let matcher = PrefixMatcher::new(&prefixes, case_sensitive, address_type, network)?;
		Ok(VanitySearch {
			prefixes, case_sensitive, compressed, address_type, network, matcher,
			raw_taproot: false,
		})
	}

	/// Generate p2tr addresses that have the public key as their output key,
	/// instead of the public key tweaked with its own hash (as in BIP 86).
	///
	/// This is a lot faster, as there is no tweak to calculate. These are
	/// addresses of the `rawtr(KEY)` descriptor, not of `tr(KEY)`.
	pub fn with_raw_taproot(mut self) -> Result<VanitySearch, String> {
		if self.address_type != VanityAddressType::P2tr {
			return Err("raw taproot is only for p2tr addresses".to_owned());
		}
		self.raw_taproot = true;
		Ok(self)
	}

	pub fn raw_taproot(&self) -> bool {
		self.raw_taproot
	}

	pub fn address_type(&self) -> VanityAddressType {
		self.address_type
	}

	pub fn network(&self) -> Network {
		self.network
	}

	/// Search with the given number of threads until `on_match` returns false.
	///
	/// `on_match` is called for every address that is found, never for more
	/// than one at the same time.
	pub fn search<F>(&self, threads: usize, on_match: F)
	where
		F: FnMut(VanityAddress) -> bool + Send,
	{
		let stop = AtomicBool::new(false);
		let attempts = AtomicU64::new(0);
		let on_match = Mutex::new(on_match);

		std::thread::scope(|s| {
			for _ in 0..threads.max(1) {
				s.spawn(|| self.search_thread(&stop, &attempts, &on_match));
			}
		});
	}

	fn search_thread<F>(&self, stop: &AtomicBool, total_attempts: &AtomicU64, on_match: &Mutex<F>)
	where
		F: FnMut(VanityAddress) -> bool + Send,
	{
		let is_taproot = self.address_type == VanityAddressType::P2tr;
		// Raw Taproot output keys are the public keys, there are no tweaks.
		let mut keys = KeyWalker::new(self.compressed, is_taproot && !self.raw_taproot);

		while !stop.load(Ordering::Relaxed) {
			let batch_len = keys.next_batch();
			let mut attempts = 0;
			let mut matched = None;

			'batch: for index in 0..batch_len {
				if is_taproot {
					attempts += 1;
					let output_key = if self.raw_taproot {
						keys.x_only_key(index)
					} else {
						keys.output_key(index)
					};
					if self.matcher.matches_output_key(&output_key) {
						matched = Some(index);
						break 'batch;
					}
					continue;
				}
				for pubkey_hash in keys.pubkey_hashes(index).iter() {
					attempts += 1;
					if self.matcher.matches(pubkey_hash) {
						matched = Some(index);
						break 'batch;
					}
				}
			}
			let attempts = total_attempts.fetch_add(attempts, Ordering::Relaxed) + attempts;

			let index = match matched {
				Some(index) => index,
				None => continue,
			};
			let secret_keys = keys.secret_keys(index);
			// Consecutive keys are related, so don't hand out more than one of them.
			keys.restart();

			// The matchers might match a little too much, so confirm the match.
			let found = secret_keys.iter()
				.map(|secret_key| self.address(*secret_key))
				.find(|(_, address)| self.matches_address(address));
			let (private_key, address) = match found {
				Some(found) => found,
				None => continue,
			};

			let mut on_match = match on_match.lock() {
				Ok(on_match) => on_match,
				// The callback panicked in another thread.
				Err(_) => {
					stop.store(true, Ordering::Relaxed);
					break;
				},
			};
			if stop.load(Ordering::Relaxed) {
				break;
			}
			if !(*on_match)(VanityAddress { private_key, address, attempts }) {
				stop.store(true, Ordering::Relaxed);
			}
		}
	}

	fn address(&self, secret_key: SecretKey) -> (PrivateKey, Address) {
		let private_key = PrivateKey {
			compressed: self.compressed,
			network: NetworkKind::from(self.network),
			inner: secret_key,
		};
		let public_key = private_key.public_key(&SECP);
		let address = match self.address_type {
			VanityAddressType::P2pkh => Address::p2pkh(public_key, self.network),
			VanityAddressType::P2wpkh => {
				let compressed = CompressedPublicKey::try_from(public_key)
					.expect("key is compressed");
				Address::p2wpkh(&compressed, self.network)
			},
			VanityAddressType::P2tr => {
				// The address can only be spent with the key, there are no scripts in it.
				let (internal_key, _) = public_key.inner.x_only_public_key();
				if self.raw_taproot {
					let output_key = TweakedPublicKey::dangerous_assume_tweaked(internal_key);
					Address::p2tr_tweaked(output_key, self.network)
				} else {
					Address::p2tr(&SECP, internal_key, None, self.network)
				}
			},
		};
		(private_key, address)
	}

	fn matches_address(&self, address: &Address) -> bool {
		let address = address.to_string();
		if self.case_sensitive {
			self.prefixes.iter().any(|p| address.starts_with(p.as_str()))
		} else {
			let address = address.to_lowercase();
			self.prefixes.iter().any(|p| address.starts_with(p.to_lowercase().as_str()))
		}
	}
}

/// The human-readable part of segwit addresses on the network.
fn bech32_hrp(network: Network) -> String {
	let address = Address::p2wsh(&ScriptBuf::new(), network).to_string();
	// There is no '1' in the data part of a segwit address.
	address[..address.rfind('1').expect("segwit address has separator")].to_owned()
}

/// The version byte of p2pkh addresses on the network.
fn p2pkh_version(network: Network) -> u8 {
	match NetworkKind::from(network) {
		NetworkKind::Main => bitcoin::constants::PUBKEY_ADDRESS_PREFIX_MAIN,
		NetworkKind::Test => bitcoin::constants::PUBKEY_ADDRESS_PREFIX_TEST,
	}
}

/// The network that a prefix is for.
///
/// For prefixes of testnet addresses, this is testnet, as they are the same
/// for testnet4 and signet.
fn network_for_prefix(prefix: &str) -> Result<Network, String> {
	let lower = prefix.to_lowercase();
	let mut candidates = Vec::new();
	for network in [Network::Bitcoin, Network::Testnet, Network::Regtest].iter().copied() {
		let segwit_start = format!("{}1", bech32_hrp(network));
		if lower.starts_with(&segwit_start) || segwit_start.starts_with(&lower) {
			candidates.push(network);
		}
	}
	if lower.starts_with('1') {
		candidates.push(Network::Bitcoin);
	}
	if lower.starts_with('m') || lower.starts_with('n') {
		candidates.push(Network::Testnet);
	}
	candidates.dedup();

	match candidates.len() {
		1 => Ok(candidates[0]),
		0 => Err(format!("can't determine the network of prefix '{}'", prefix)),
		_ => Err(format!(
			"prefix '{}' can be for multiple networks, make it longer or pass a network flag",
			prefix,
		)),
	}
}

/// The type of address that a prefix is for.
fn address_type_for_prefix(prefix: &str, network: Network) -> Result<VanityAddressType, String> {
	let hrp = bech32_hrp(network);
	let p2wpkh_start = format!("{}1q", hrp);
	let p2tr_start = format!("{}1p", hrp);

	let prefix = prefix.to_lowercase();
	if prefix.starts_with(&p2wpkh_start) {
		Ok(VanityAddressType::P2wpkh)
	} else if prefix.starts_with(&p2tr_start) {
		Ok(VanityAddressType::P2tr)
	} else if p2wpkh_start.starts_with(&prefix) {
		Err(format!(
			"prefix '{}' is ambiguous: start with {} for p2wpkh or with {} for p2tr",
			prefix, p2wpkh_start, p2tr_start,
		))
	} else {
		Ok(VanityAddressType::P2pkh)
	}
}

/// A point on the curve. Both coordinates are normalized, the ones that come
/// out of `add_points` only weakly.
#[derive(Clone, Copy)]
struct Point {
	x: FieldElement,
	y: FieldElement,
}

impl Point {
	fn from_public_key(public_key: &secp256k1::PublicKey) -> Self {
		let bytes = public_key.serialize_uncompressed();
		Self {
			x: field_element(&bytes[1..33]),
			y: field_element(&bytes[33..65]),
		}
	}
}

fn field_element(bytes: &[u8]) -> FieldElement {
	let bytes: [u8; 32] = bytes.try_into().expect("32 bytes");
	Option::<FieldElement>::from(FieldElement::from_bytes(&FieldBytes::from(bytes)))
		.expect("valid field element")
}

/// Multiples of the generator point G, shared by all the threads.
struct GeneratorMultiples {
	// 1G, 2G, .. up to HALF_BATCH_SIZE times G.
	multiples: Vec<Point>,
	// BATCH_SIZE times G, the distance between the centers of two batches.
	step: Point,
}

impl GeneratorMultiples {
	fn get() -> &'static Self {
		static MULTIPLES: OnceLock<GeneratorMultiples> = OnceLock::new();

		MULTIPLES.get_or_init(|| {
			let one = SecretKey::from_slice(&secp256k1::constants::ONE).expect("valid key");
			let generator = secp256k1::PublicKey::from_secret_key(&SECP, &one);

			let mut multiple = generator;
			let mut multiples = Vec::with_capacity(BATCH_SIZE);
			for _ in 0..BATCH_SIZE {
				multiples.push(Point::from_public_key(&multiple));
				multiple = multiple.combine(&generator).expect("valid point");
			}

			let step = multiples[BATCH_SIZE - 1];
			multiples.truncate(HALF_BATCH_SIZE);
			Self { multiples, step }
		})
	}
}

/// Multiples of G that add up to any tweak times G, shared by all the threads.
///
/// A tweak is split up in windows of `TWEAK_WINDOW_BITS` bits, and for every
/// window there is a multiple for each of the values it can have. That makes
/// a tweak times G the sum of one multiple per window.
struct TweakMultiples {
	// The multiples of the first window (the lowest bits of the tweak),
	// followed by those of the next ones.
	multiples: Vec<Point>,
}

impl TweakMultiples {
	fn get() -> &'static Self {
		static MULTIPLES: OnceLock<TweakMultiples> = OnceLock::new();

		MULTIPLES.get_or_init(|| {
			let mut multiples = Vec::with_capacity(TWEAK_WINDOWS * TWEAK_WINDOW_SIZE);
			let mut products = Vec::new();
			// The value 1 of every window, times G.
			let mut ones = Vec::with_capacity(TWEAK_WINDOWS);

			for window in 0..TWEAK_WINDOWS {
				let bit = window * TWEAK_WINDOW_BITS;
				let mut one = [0u8; 32];
				one[31 - bit / 8] = 1 << (bit % 8);
				let one = SecretKey::from_slice(&one).expect("valid key");
				let one = secp256k1::PublicKey::from_secret_key(&SECP, &one);
				let two = one.combine(&one).expect("valid point");

				// There is no point to add for a value of zero, so these are
				// the multiples for the values plus one.
				let start = multiples.len();
				multiples.push(Point::from_public_key(&one));
				multiples.push(Point::from_public_key(&two));
				while multiples.len() - start < TWEAK_WINDOW_SIZE {
					// Adding the last multiple to the ones before it gives
					// the ones that follow it.
					let len = multiples.len() - start;
					let last = multiples[start + len - 1];
					let more = (len - 1).min(TWEAK_WINDOW_SIZE - len);
					multiples.extend_from_within(start..start + more);
					let is_added = add_points(&mut multiples[start + len..], |_| &last, &mut products);
					assert!(is_added, "failed to add points");
				}
				ones.push(one);
			}

			// That is a one too many for every window, the multiples of the
			// first window make up for all of them.
			let ones = ones.iter().collect::<Vec<_>>();
			let ones = secp256k1::PublicKey::combine_keys(&ones).expect("valid point");
			let mut minus_ones = Point::from_public_key(&ones);
			minus_ones.y = minus_ones.y.negate(1).normalize();
			let first_window = &mut multiples[..TWEAK_WINDOW_SIZE];
			let is_added = add_points(first_window, |_| &minus_ones, &mut products);
			assert!(is_added, "failed to add points");

			Self { multiples }
		})
	}
}

/// Adds another point to every one of the points, `other` gives the point to
/// add by index. All the divisions this takes are replaced by a single one
/// (and some multiplications) using Montgomery's trick.
///
/// Returns false if one of the points is the same as (or the inverse of) the
/// point to add to it, the points are left as they are in that case.
///
/// The coordinates of the sums are only weakly normalized, as that is all it
/// takes to add to them again.
fn add_points<'a>(
	points: &mut [Point],
	other: impl Fn(usize) -> &'a Point,
	products: &mut Vec<FieldElement>,
) -> bool {
	// What we have to divide by for every point, as the product of all of
	// them before the point.
	products.clear();
	let mut product = FieldElement::ONE;
	for (i, point) in points.iter().enumerate() {
		products.push(product);
		product = product.mul(&(other(i).x + point.x.negate(1)));
	}
	let mut inverse = match Option::<FieldElement>::from(product.normalize().invert()) {
		Some(inverse) => inverse,
		None => return false,
	};

	for (i, point) in points.iter_mut().enumerate().rev() {
		let other = other(i);
		let delta_inverse = inverse.mul(&products[i]);
		inverse = inverse.mul(&(other.x + point.x.negate(1)));

		let slope = (other.y + point.y.negate(1)).mul(&delta_inverse);
		let x = (slope.square() + (point.x + other.x).negate(2)).normalize_weak();
		let y = (slope.mul(&(point.x + x.negate(1))) + point.y.negate(1)).normalize_weak();
		*point = Point { x, y };
	}
	true
}

/// The output keys of a batch, these are what Taproot addresses encode.
///
/// An output key is the public key plus a tweak times G. The tweak is a hash
/// of the public key, so there is no cheap way to get from the output key of
/// one key to that of the next one. Every one of them takes adding a point
/// per window of the tweak, which is why Taproot addresses are a lot slower
/// than the other ones.
struct OutputKeys {
	multiples: &'static TweakMultiples,
	// The public keys of the batch, that are turned into the output keys by
	// adding the tweaks to them one window at a time.
	points: Vec<Point>,
	// For every tweak, which of the multiples to add for each of the windows.
	tweaks: Vec<[u32; TWEAK_WINDOWS]>,
	// Scratch space for the divisions.
	products: Vec<FieldElement>,
}

impl OutputKeys {
	fn new() -> Self {
		Self {
			multiples: TweakMultiples::get(),
			points: vec![Point { x: FieldElement::ZERO, y: FieldElement::ZERO }; BATCH_SIZE],
			tweaks: vec![[0u32; TWEAK_WINDOWS]; BATCH_SIZE],
			products: Vec::with_capacity(BATCH_SIZE),
		}
	}

	/// Calculate the output keys of a batch of public keys, `x` followed by
	/// `y`. Returns false in the practically impossible case that this can't
	/// be done for one of them.
	fn calculate(&mut self, public_keys: &[[u8; 64]]) -> bool {
		let keys = public_keys.iter().zip(&mut self.points).zip(&mut self.tweaks);
		for ((public_key, point), tweak) in keys {
			// Taproot only uses the `x` of a public key, the `y` is always
			// the even one.
			let x = field_element(&public_key[..32]);
			let mut y = field_element(&public_key[32..]);
			if public_key[63] & 1 == 1 {
				y = y.negate(1).normalize();
			}
			*point = Point { x, y };

			// The address can only be spent with the key, so the tweak is
			// the hash of nothing but the key.
			let mut engine = TapTweakHash::engine();
			engine.input(&public_key[..32]);
			let hash = TapTweakHash::from_engine(engine).to_byte_array();

			let mut high = u128::from_be_bytes(hash[..16].try_into().unwrap());
			let mut low = u128::from_be_bytes(hash[16..].try_into().unwrap());
			for (window, multiple) in tweak.iter_mut().enumerate() {
				let value = low as usize % TWEAK_WINDOW_SIZE;
				*multiple = (window * TWEAK_WINDOW_SIZE + value) as u32;
				low = low >> TWEAK_WINDOW_BITS | high << (128 - TWEAK_WINDOW_BITS);
				high >>= TWEAK_WINDOW_BITS;
			}
		}

		let multiples = &self.multiples.multiples;
		let tweaks = &self.tweaks;
		let points = &mut self.points;
		let products = &mut self.products;
		(0..TWEAK_WINDOWS).all(|window| {
			let multiple = |i: usize| &multiples[tweaks[i][window] as usize];
			add_points(points, multiple, products)
		})
	}
}

/// Walks over consecutive keys in batches, starting at a random key.
///
/// Deriving a public key from a secret key is by far the most expensive step
/// of generating an address, so that is only done for the key we start at.
/// The public key of secret key `k + i` is the public key of `k` plus `i`
/// times G, which is a lot cheaper to calculate:
///
/// - Adding two points takes a division, which is the expensive part of it.
///   All the divisions of a batch are replaced by a single one (and some
///   multiplications) using Montgomery's trick.
/// - The points `i` times G and minus `i` times G only differ in the sign of
///   `y`, so adding and subtracting it from the center of the batch can share
///   that division.
/// - Negating a public key gives the public key of the negated secret key. As
///   that again only changes the sign of `y`, every point is used for two
///   keys. Not for Taproot addresses though, as those don't look at the sign
///   of `y`: both keys have the same address.
struct KeyWalker {
	compressed: bool,
	multiples: &'static GeneratorMultiples,
	// The secret key at offset 0.
	base: SecretKey,
	// The offset of the center of the current batch.
	center_offset: u64,
	// The center of the next batch.
	next_center: Point,
	next_center_offset: u64,
	// The points of the current batch, `x` followed by `y`. `y` is only there
	// for uncompressed keys and Taproot addresses, it is not needed for the
	// hash of a compressed key.
	points: Vec<[u8; 64]>,
	// Scratch space for the divisions.
	deltas: Vec<FieldElement>,
	products: Vec<FieldElement>,
	// The output keys of the current batch, only there for Taproot addresses.
	output_keys: Option<OutputKeys>,
}

impl KeyWalker {
	fn new(compressed: bool, taproot: bool) -> Self {
		let mut walker = Self {
			compressed,
			multiples: GeneratorMultiples::get(),
			base: random_secret_key(),
			center_offset: 0,
			next_center: Point { x: FieldElement::ZERO, y: FieldElement::ZERO },
			next_center_offset: 0,
			points: vec![[0u8; 64]; BATCH_SIZE],
			deltas: vec![FieldElement::ZERO; HALF_BATCH_SIZE + 1],
			products: vec![FieldElement::ZERO; HALF_BATCH_SIZE + 1],
			output_keys: if taproot { Some(OutputKeys::new()) } else { None },
		};
		walker.restart();
		walker
	}

	/// Start over at a new random key. The current batch is not valid until
	/// `next_batch` is called.
	fn restart(&mut self) {
		loop {
			self.base = random_secret_key();
			self.next_center_offset = HALF_BATCH_SIZE as u64;
			let center = match secret_key_at(&self.base, self.next_center_offset) {
				Some(center) => center,
				None => continue,
			};
			let center = secp256k1::PublicKey::from_secret_key(&SECP, &center);
			self.next_center = Point::from_public_key(&center);
			return;
		}
	}

	/// Move on to the next batch of keys, returns the number of points in it.
	/// Every point is the public key of two secret keys.
	fn next_batch(&mut self) -> usize {
		// Practically this always works, if not just start over somewhere else.
		while self.next_center_offset > u64::MAX / 2 || !self.calculate_batch() {
			self.restart();
		}
		BATCH_SIZE
	}

	fn calculate_batch(&mut self) -> bool {
		let multiples = self.multiples;
		let has_y = !self.compressed || self.output_keys.is_some();
		let center = self.next_center;
		let neg_center_x = center.x.negate(1);
		let neg_center_y = center.y.negate(1);

		// What we have to divide by to add every multiple (and the step) to
		// the center.
		for (delta, multiple) in self.deltas.iter_mut().zip(&multiples.multiples) {
			*delta = multiple.x + neg_center_x;
		}
		self.deltas[HALF_BATCH_SIZE] = multiples.step.x + neg_center_x;

		// Montgomery's trick: invert the product of all of them, and get the
		// individual inverses out of that.
		let mut product = self.deltas[0];
		self.products[0] = product;
		for i in 1..=HALF_BATCH_SIZE {
			product = product.mul(&self.deltas[i]);
			self.products[i] = product;
		}
		let mut inverse = match Option::<FieldElement>::from(product.normalize().invert()) {
			Some(inverse) => inverse,
			// One of the points is the same as (or the inverse of) the center.
			None => return false,
		};
		let mut next_center = center;

		for i in (0..=HALF_BATCH_SIZE).rev() {
			let delta_inverse = if i == 0 {
				inverse
			} else {
				inverse.mul(&self.products[i - 1])
			};
			inverse = inverse.mul(&self.deltas[i]);

			if i == HALF_BATCH_SIZE {
				let step = &multiples.step;
				let slope = (step.y + neg_center_y).mul(&delta_inverse);
				let x = (slope.square() + (center.x + step.x).negate(2)).normalize();
				let y = (slope.mul(&(center.x + x.negate(1))) + neg_center_y).normalize();
				next_center = Point { x, y };
				continue;
			}

			let multiple = &multiples.multiples[i];
			let neg_x_sum = (center.x + multiple.x).negate(2);

			// The center plus the multiple.
			let slope = (multiple.y + neg_center_y).mul(&delta_inverse);
			let x = (slope.square() + neg_x_sum).normalize();
			let point = &mut self.points[1 + 2 * i];
			point[..32].copy_from_slice(&x.to_bytes());
			if has_y {
				let y = (slope.mul(&(center.x + x.negate(1))) + neg_center_y).normalize();
				point[32..].copy_from_slice(&y.to_bytes());
			}

			// The center minus the multiple.
			let slope = (multiple.y + center.y).negate(2).mul(&delta_inverse);
			let x = (slope.square() + neg_x_sum).normalize();
			let point = &mut self.points[2 + 2 * i];
			point[..32].copy_from_slice(&x.to_bytes());
			if has_y {
				let y = (slope.mul(&(center.x + x.negate(1))) + neg_center_y).normalize();
				point[32..].copy_from_slice(&y.to_bytes());
			}
		}

		self.points[0][..32].copy_from_slice(&center.x.to_bytes());
		self.points[0][32..].copy_from_slice(&center.y.to_bytes());

		if let Some(ref mut output_keys) = self.output_keys {
			if !output_keys.calculate(&self.points) {
				return false;
			}
		}

		self.center_offset = self.next_center_offset;
		self.next_center = next_center;
		self.next_center_offset += BATCH_SIZE as u64;
		true
	}

	/// The hash160 of both public keys of a point in the current batch, this
	/// is what addresses encode.
	fn pubkey_hashes(&self, index: usize) -> [[u8; 20]; 2] {
		let point = &self.points[index];

		if self.compressed {
			let mut public_key = [0u8; 33];
			public_key[1..].copy_from_slice(&point[..32]);
			public_key[0] = 2;
			let even = hash160::Hash::hash(&public_key).to_byte_array();
			public_key[0] = 3;
			let odd = hash160::Hash::hash(&public_key).to_byte_array();
			[even, odd]
		} else {
			let mut public_key = [0u8; 65];
			public_key[0] = 4;
			public_key[1..].copy_from_slice(point);
			let positive = hash160::Hash::hash(&public_key).to_byte_array();

			let y = field_element(&point[32..]);
			public_key[33..].copy_from_slice(&y.negate(1).normalize().to_bytes());
			let negative = hash160::Hash::hash(&public_key).to_byte_array();
			[positive, negative]
		}
	}

	/// The output key of a point in the current batch, this is what a Taproot
	/// address encodes. It is the same one for both secret keys of the point.
	fn output_key(&self, index: usize) -> [u8; 32] {
		let output_keys = self.output_keys.as_ref().expect("walker is for taproot");
		// This is the only place that needs it fully normalized.
		output_keys.points[index].x.normalize().to_bytes().into()
	}

	/// The `x` of a point in the current batch, this is what a raw Taproot
	/// address encodes. It is the same one for both secret keys of the point.
	fn x_only_key(&self, index: usize) -> [u8; 32] {
		self.points[index][..32].try_into().unwrap()
	}

	/// The secret keys of a point in the current batch. Which of the two
	/// belongs to which of the hashes is not known.
	fn secret_keys(&self, index: usize) -> [SecretKey; 2] {
		let distance = (index as u64 + 1) / 2;
		let offset = if index % 2 == 1 {
			self.center_offset + distance
		} else {
			self.center_offset - distance
		};
		let secret_key = secret_key_at(&self.base, offset).expect("valid secret key");
		[secret_key, secret_key.negate()]
	}
}

fn secret_key_at(base: &SecretKey, offset: u64) -> Option<SecretKey> {
	let mut tweak = [0u8; 32];
	tweak[24..].copy_from_slice(&offset.to_be_bytes());
	let tweak = Scalar::from_be_bytes(tweak).ok()?;
	base.add_tweak(&tweak).ok()
}

fn random_secret_key() -> SecretKey {
	SecretKey::new(&mut secp256k1::rand::thread_rng())
}

/// Matches prefixes against a public key hash (or the output key for Taproot
/// addresses), without creating an address.
///
/// It might match a little too much, so a match has to be confirmed against
/// the actual address.
enum PrefixMatcher {
	Bech32(Vec<Bech32Prefix>),
	Taproot(Vec<TaprootPrefix>),
	Base58(Vec<Base58Range>),
	// Fallback for when there would be too many ranges.
	Base58Slow { prefixes: Vec<Vec<u8>>, case_sensitive: bool, version: u8 },
}

/// The bits of a public key hash that are set by a Bech32 prefix.
struct Bech32Prefix {
	// The first 16 bytes and the last 4 bytes of the hash.
	mask: (u128, u32),
	bits: (u128, u32),
}

/// The bits of an output key that are set by a Taproot prefix.
struct TaprootPrefix {
	// The first 16 bytes and the last 16 bytes of the key.
	mask: (u128, u128),
	bits: (u128, u128),
}

/// A range of public key hashes, that has all the Base58 addresses starting
/// with a certain prefix. Both ends are inclusive.
///
/// The addresses of the hashes at the very ends of the range might not start
/// with the prefix, as that depends on the checksum.
struct Base58Range {
	first: [u8; 20],
	last: [u8; 20],
}

impl PrefixMatcher {
	fn new(
		prefixes: &[String],
		case_sensitive: bool,
		address_type: VanityAddressType,
		network: Network,
	) -> Result<Self, String> {
		let invalid = |prefix: &str| {
			format!("no {} {} address can start with '{}'", network, address_type.as_str(), prefix)
		};

		match address_type {
			VanityAddressType::P2pkh => {},
			VanityAddressType::P2wpkh => {
				let start = format!("{}1q", bech32_hrp(network));
				let prefixes = prefixes.iter().map(|prefix| {
					Bech32Prefix::new(prefix, &start).ok_or_else(|| invalid(prefix))
				});
				return Ok(Self::Bech32(prefixes.collect::<Result<_, _>>()?));
			},
			VanityAddressType::P2tr => {
				let start = format!("{}1p", bech32_hrp(network));
				let prefixes = prefixes.iter().map(|prefix| {
					TaprootPrefix::new(prefix, &start).ok_or_else(|| invalid(prefix))
				});
				return Ok(Self::Taproot(prefixes.collect::<Result<_, _>>()?));
			},
		}

		let version = p2pkh_version(network);
		let mut ranges = Vec::new();
		let mut too_many = false;
		for prefix in prefixes {
			let is_valid = prefix.bytes().all(|c| {
				BASE58_CHARSET.contains(&c) || (!case_sensitive && (
					BASE58_CHARSET.contains(&c.to_ascii_lowercase())
						|| BASE58_CHARSET.contains(&c.to_ascii_uppercase())
				))
			});
			if !is_valid {
				return Err(invalid(prefix));
			}

			// When there are too many variants, check that at least the first
			// characters can be matched.
			let mut checked = prefix.as_bytes();
			let mut variants = Vec::new();
			while !base58_variants(checked, case_sensitive, &mut variants) {
				too_many = true;
				checked = &checked[..checked.len() / 2];
				variants.clear();
			}

			let len = ranges.len();
			for variant in &variants {
				base58_ranges(variant, version, &mut ranges);
			}
			if ranges.len() == len {
				return Err(invalid(prefix));
			}
		}

		if too_many {
			let prefixes = prefixes.iter().map(|prefix| {
				if case_sensitive {
					prefix.clone().into_bytes()
				} else {
					prefix.to_lowercase().into_bytes()
				}
			});
			return Ok(Self::Base58Slow {
				prefixes: prefixes.collect(),
				case_sensitive,
				version,
			});
		}

		ranges.sort_by_key(|range| range.first);
		// Merge the ranges that overlap, so there is only one that can match.
		let mut merged: Vec<Base58Range> = Vec::with_capacity(ranges.len());
		for range in ranges {
			match merged.last_mut() {
				Some(previous) if range.first <= previous.last => {
					previous.last = previous.last.max(range.last);
				},
				_ => merged.push(range),
			}
		}
		Ok(Self::Base58(merged))
	}

	fn matches(&self, pubkey_hash: &[u8; 20]) -> bool {
		match self {
			Self::Bech32(prefixes) => {
				let head = u128::from_be_bytes(pubkey_hash[..16].try_into().unwrap());
				let tail = u32::from_be_bytes(pubkey_hash[16..].try_into().unwrap());
				prefixes.iter().any(|prefix| {
					head & prefix.mask.0 == prefix.bits.0 && tail & prefix.mask.1 == prefix.bits.1
				})
			},
			// These have no public key hash in them.
			Self::Taproot(_) => false,
			Self::Base58(ranges) => {
				let index = ranges.partition_point(|range| range.first <= *pubkey_hash);
				index > 0 && *pubkey_hash <= ranges[index - 1].last
			},
			Self::Base58Slow { prefixes, case_sensitive, version } => {
				let mut payload = [0u8; 21];
				payload[0] = *version;
				payload[1..].copy_from_slice(pubkey_hash);
				let mut address = bitcoin::base58::encode_check(&payload).into_bytes();
				if !case_sensitive {
					address.make_ascii_lowercase();
				}
				prefixes.iter().any(|prefix| address.starts_with(prefix))
			},
		}
	}

	/// Like `matches`, for the output key of a Taproot address.
	fn matches_output_key(&self, output_key: &[u8; 32]) -> bool {
		let prefixes = match self {
			Self::Taproot(prefixes) => prefixes,
			_ => return false,
		};
		let head = u128::from_be_bytes(output_key[..16].try_into().unwrap());
		let tail = u128::from_be_bytes(output_key[16..].try_into().unwrap());
		prefixes.iter().any(|prefix| {
			head & prefix.mask.0 == prefix.bits.0 && tail & prefix.mask.1 == prefix.bits.1
		})
	}
}

impl Bech32Prefix {
	/// Returns nothing if there are no addresses starting with the prefix.
	fn new(prefix: &str, start: &str) -> Option<Self> {
		let len = start.len() + P2WPKH_DATA_LEN;
		let (mask, bits) = bech32_bits::<20>(prefix, start.as_bytes(), len)?;

		let split = |bytes: [u8; 20]| {
			let head = u128::from_be_bytes(bytes[..16].try_into().unwrap());
			let tail = u32::from_be_bytes(bytes[16..].try_into().unwrap());
			(head, tail)
		};
		Some(Self { mask: split(mask), bits: split(bits) })
	}
}

impl TaprootPrefix {
	/// Returns nothing if there are no addresses starting with the prefix.
	fn new(prefix: &str, start: &str) -> Option<Self> {
		let len = start.len() + P2TR_DATA_LEN;
		let (mask, bits) = bech32_bits::<32>(prefix, start.as_bytes(), len)?;

		let split = |bytes: [u8; 32]| {
			let head = u128::from_be_bytes(bytes[..16].try_into().unwrap());
			let tail = u128::from_be_bytes(bytes[16..].try_into().unwrap());
			(head, tail)
		};
		Some(Self { mask: split(mask), bits: split(bits) })
	}
}

/// The bits that are set by a Bech32 prefix in the `N` bytes that an address
/// encodes, as a mask and the value of the bits in it. `start` is what all the
/// addresses start with, and `len` how long they are without the checksum.
///
/// Returns nothing if there are no addresses starting with the prefix.
fn bech32_bits<const N: usize>(
	prefix: &str,
	start: &[u8],
	len: usize,
) -> Option<([u8; N], [u8; N])> {
	let prefix = prefix.to_lowercase().into_bytes();
	// The checksum of a Bech32 address is not looked at here.
	let prefix = &prefix[..prefix.len().min(len)];

	let start_len = prefix.len().min(start.len());
	if prefix[..start_len] != start[..start_len] {
		return None;
	}

	// Every character sets 5 bits.
	let mut mask = [0u8; N];
	let mut bits = [0u8; N];
	for (i, character) in prefix[start_len..].iter().enumerate() {
		let value = BECH32_CHARSET.iter().position(|c| c == character)?;
		for bit in 0..5 {
			let position = i * 5 + bit;
			let is_set = value & (0x10 >> bit) != 0;
			if position >= N * 8 {
				// The last character has some bits left, they are always zero.
				if is_set {
					return None;
				}
				continue;
			}
			mask[position / 8] |= 0x80 >> (position % 8);
			if is_set {
				bits[position / 8] |= 0x80 >> (position % 8);
			}
		}
	}
	Some((mask, bits))
}

/// Adds all the ways to write a prefix in Base58 to `variants`, which is more
/// than one if upper and lowercase don't matter. Returns false if there are
/// too many of them.
fn base58_variants(prefix: &[u8], case_sensitive: bool, variants: &mut Vec<Vec<u8>>) -> bool {
	let start = variants.len();
	variants.push(Vec::with_capacity(prefix.len()));

	for character in prefix {
		let mut options = vec![*character];
		if !case_sensitive {
			options = vec![character.to_ascii_lowercase(), character.to_ascii_uppercase()];
			options.dedup();
		}
		options.retain(|option| BASE58_CHARSET.contains(option));

		// With no options left this removes all the variants, as there are no
		// addresses starting with the prefix.
		let unfinished = variants.split_off(start);
		for variant in &unfinished {
			for option in &options {
				let mut variant = variant.clone();
				variant.push(*option);
				variants.push(variant);
			}
		}
		if variants.len() > BASE58_MAX_VARIANTS {
			return false;
		}
	}
	true
}

/// Adds the ranges of public key hashes that have all the addresses starting
/// with a (case sensitive) prefix to `ranges`, for addresses with the given
/// version byte.
fn base58_ranges(prefix: &[u8], version: u8, ranges: &mut Vec<Base58Range>) {
	// Every leading '1' of an address is a leading zero byte of the payload,
	// the rest of the address is the rest of the payload as a number.
	let zeros = prefix.iter().take_while(|character| **character == b'1').count();
	let digits = prefix[zeros..]
		.iter()
		.map(|character| BASE58_CHARSET.iter().position(|c| c == character).unwrap() as u8)
		.collect::<Vec<u8>>();

	// The smallest and largest payload with this version byte and, for
	// version zero, this many leading zero bytes.
	let mut smallest = [0u8; BASE58_PAYLOAD_LEN];
	let mut largest = [0xffu8; BASE58_PAYLOAD_LEN];
	if version == 0 {
		// The first byte of the payload is the version, which is zero.
		if zeros == 0 || zeros > BASE58_PAYLOAD_LEN {
			return;
		}
		largest[..zeros].fill(0);
	} else {
		// There are no leading zero bytes.
		if zeros > 0 {
			return;
		}
		smallest[0] = version;
		largest[0] = version;
	}

	let mut add_range = |first: [u8; BASE58_PAYLOAD_LEN], last: [u8; BASE58_PAYLOAD_LEN]| {
		ranges.push(Base58Range {
			first: first[1..21].try_into().unwrap(),
			last: last[1..21].try_into().unwrap(),
		});
	};

	if digits.is_empty() {
		// Only leading zeros, more of them is fine as well.
		add_range(smallest, largest);
		return;
	}
	if version == 0 {
		if zeros == BASE58_PAYLOAD_LEN {
			return;
		}
		// There are no more leading zeros than the ones in the prefix.
		smallest[zeros] = 1;
	}

	// The prefix sets the first digits of the number, try every number of
	// digits that could follow them.
	for len in digits.len()..=BASE58_MAX_ADDRESS_LEN {
		let number = |fill: u8| {
			let mut number = [0u8; BASE58_PAYLOAD_LEN];
			let fill = std::iter::repeat(fill).take(len - digits.len());
			for digit in digits.iter().copied().chain(fill) {
				let mut carry = u32::from(digit);
				for byte in number.iter_mut().rev() {
					carry += u32::from(*byte) * 58;
					*byte = carry as u8;
					carry >>= 8;
				}
				if carry != 0 {
					return None;
				}
			}
			Some(number)
		};

		// Too large numbers have no first, too small ones have a last that
		// is too small.
		let first = match number(0) {
			Some(first) => first,
			None => break,
		};
		let last = number(57).unwrap_or(largest);
		if first > largest || last < smallest {
			continue;
		}
		add_range(first.max(smallest), last.min(largest));
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	fn address(
		secret_key: SecretKey,
		compressed: bool,
		address_type: VanityAddressType,
		network: Network,
	) -> Address {
		search_address(secret_key, compressed, false, address_type, network)
	}

	fn search_address(
		secret_key: SecretKey,
		compressed: bool,
		raw_taproot: bool,
		address_type: VanityAddressType,
		network: Network,
	) -> Address {
		let search = VanitySearch {
			prefixes: vec![],
			case_sensitive: false,
			compressed,
			raw_taproot,
			address_type,
			network,
			matcher: PrefixMatcher::Bech32(vec![]),
		};
		search.address(secret_key).1
	}

	#[test]
	fn address_types() {
		let tp = |p: &str, n: Network| address_type_for_prefix(p, n);
		assert_eq!(tp("1abc", Network::Bitcoin), Ok(VanityAddressType::P2pkh));
		assert_eq!(tp("bc1qabc", Network::Bitcoin), Ok(VanityAddressType::P2wpkh));
		assert_eq!(tp("BC1PABC", Network::Bitcoin), Ok(VanityAddressType::P2tr));
		assert!(tp("bc1", Network::Bitcoin).is_err());
		assert_eq!(tp("tb1qabc", Network::Testnet), Ok(VanityAddressType::P2wpkh));
		assert_eq!(tp("bcrt1p", Network::Regtest), Ok(VanityAddressType::P2tr));
		assert_eq!(tp("mabc", Network::Signet), Ok(VanityAddressType::P2pkh));

		let new = |p: &str, n: Network| VanitySearch::new(vec![p.to_owned()], false, true, Some(n));
		assert!(new("bc1qb", Network::Bitcoin).is_err());
		assert!(new("bc1pqz", Network::Bitcoin).is_ok());
		assert!(new("2abc", Network::Bitcoin).is_err());
		assert!(new("1abc", Network::Testnet).is_err());
		// Testnet p2pkh addresses go from mf.. up to n4..
		assert!(new("mabc", Network::Testnet).is_err());
		assert!(new("mzabc", Network::Testnet).is_ok());
		assert!(new("N2bc", Network::Testnet).is_ok());
		assert!(new("n5bc", Network::Testnet).is_err());
		assert!(new("1abc", Network::Bitcoin).is_ok());
		assert!(new("10", Network::Bitcoin).is_err());
		let long = "1".to_owned() + &"a".repeat(30);
		assert!(new(&long, Network::Bitcoin).is_ok());
		let long = "1".to_owned() + &"a".repeat(28) + "0";
		assert!(new(&long, Network::Bitcoin).is_err());
		let net = Some(Network::Bitcoin);
		assert!(VanitySearch::new(vec!["bc1qq".into()], false, false, net).is_err());
		assert!(VanitySearch::new(vec!["1q".into(), "bc1qq".into()], false, true, net).is_err());
		let raw = |p: &str| VanitySearch::new(vec![p.to_owned()], false, true, net)
			.unwrap().with_raw_taproot();
		assert!(raw("bc1pq").is_ok());
		assert!(raw("bc1qq").is_err());
		assert!(raw("1q").is_err());
	}

	#[test]
	fn networks() {
		assert_eq!(network_for_prefix("1abc"), Ok(Network::Bitcoin));
		assert_eq!(network_for_prefix("bc1q"), Ok(Network::Bitcoin));
		assert_eq!(network_for_prefix("BC1P"), Ok(Network::Bitcoin));
		assert_eq!(network_for_prefix("tb1q"), Ok(Network::Testnet));
		assert_eq!(network_for_prefix("t"), Ok(Network::Testnet));
		assert_eq!(network_for_prefix("mzab"), Ok(Network::Testnet));
		assert_eq!(network_for_prefix("N2"), Ok(Network::Testnet));
		assert_eq!(network_for_prefix("bcrt1q"), Ok(Network::Regtest));
		assert_eq!(network_for_prefix("bcr"), Ok(Network::Regtest));
		assert!(network_for_prefix("b").is_err());
		assert!(network_for_prefix("bc").is_err());
		assert!(network_for_prefix("3abc").is_err());
		assert!(network_for_prefix("").is_err());

		let new = |p: &[&str]| {
			let prefixes = p.iter().map(|p| p.to_string()).collect();
			VanitySearch::new(prefixes, false, true, None).map(|s| s.network())
		};
		assert_eq!(new(&["tb1qa", "tb1qc"]), Ok(Network::Testnet));
		assert_eq!(new(&["bcrt1pa"]), Ok(Network::Regtest));
		assert_eq!(new(&["mzab", "n2ab"]), Ok(Network::Testnet));
		assert_eq!(new(&["1ab"]), Ok(Network::Bitcoin));
		assert!(new(&["1ab", "mzab"]).is_err());
		// An explicit network takes precedence.
		let signet = VanitySearch::new(vec!["tb1qa".into()], false, true, Some(Network::Signet));
		assert_eq!(signet.map(|s| s.network()), Ok(Network::Signet));
	}

	#[test]
	fn walked_keys_match_their_secret_key() {
		for compressed in [true, false].iter().copied() {
			let mut keys = KeyWalker::new(compressed, false);
			let mut seen = std::collections::HashSet::new();

			for batch in 0..6 {
				if batch == 3 {
					keys.restart();
				}
				let batch_len = keys.next_batch();
				for index in 0..batch_len {
					let mut expected = keys.secret_keys(index).iter().map(|secret_key| {
						let private_key = PrivateKey {
							compressed,
							network: NetworkKind::Main,
							inner: *secret_key,
						};
						private_key.public_key(&SECP).pubkey_hash().to_byte_array()
					}).collect::<Vec<_>>();
					let mut hashes = keys.pubkey_hashes(index).to_vec();
					expected.sort();
					hashes.sort();
					assert_eq!(hashes, expected);
					// No key is tried twice.
					assert!(hashes.into_iter().all(|hash| seen.insert(hash)));
				}
			}
		}
	}

	#[test]
	fn walked_output_keys_match_their_secret_key() {
		let mut keys = KeyWalker::new(true, true);
		let mut seen = std::collections::HashSet::new();

		for batch in 0..3 {
			if batch == 2 {
				keys.restart();
			}
			let batch_len = keys.next_batch();
			for index in 0..batch_len {
				let output_key = keys.output_key(index);
				// Both secret keys have the same address.
				for secret_key in keys.secret_keys(index).iter() {
					let addr = address(*secret_key, true, VanityAddressType::P2tr, Network::Bitcoin);
					let program = addr.witness_program().unwrap();
					assert_eq!(program.program().as_bytes(), output_key);
				}
				// No key is tried twice.
				assert!(seen.insert(output_key));
			}
		}
	}

	#[test]
	fn walked_raw_taproot_keys_match_their_secret_key() {
		let mut keys = KeyWalker::new(true, false);
		let batch_len = keys.next_batch();
		for index in 0..batch_len {
			let output_key = keys.x_only_key(index);
			// Both secret keys have the same address.
			for secret_key in keys.secret_keys(index).iter() {
				let addr = search_address(
					*secret_key, true, true, VanityAddressType::P2tr, Network::Bitcoin,
				);
				let program = addr.witness_program().unwrap();
				assert_eq!(program.program().as_bytes(), output_key);
				// Not the same address as a tweaked one.
				let tweaked = address(*secret_key, true, VanityAddressType::P2tr, Network::Bitcoin);
				assert_ne!(addr, tweaked);
			}
		}
	}

	#[test]
	fn matcher_agrees_with_address() {
		let mut keys = KeyWalker::new(true, false);
		keys.next_batch();

		for network in [Network::Bitcoin, Network::Testnet, Network::Regtest].iter().copied() {
			for index in 0..100 {
				for (address_type, case_sensitive, len) in [
					(VanityAddressType::P2wpkh, false, 3),
					(VanityAddressType::P2wpkh, false, 7),
					(VanityAddressType::P2wpkh, false, 36),
					(VanityAddressType::P2tr, false, 3),
					(VanityAddressType::P2tr, false, 7),
					(VanityAddressType::P2tr, false, 31),
					(VanityAddressType::P2tr, false, 56),
					(VanityAddressType::P2pkh, true, 1),
					(VanityAddressType::P2pkh, true, 4),
					(VanityAddressType::P2pkh, false, 4),
					(VanityAddressType::P2pkh, false, 9),
					(VanityAddressType::P2pkh, true, 34),
					// Too many variants, this uses the slow matcher.
					(VanityAddressType::P2pkh, false, 30),
				].iter().copied() {
					let is_p2pkh = address_type == VanityAddressType::P2pkh;
					let secret_key = keys.secret_keys(index)[0];
					let addr = address(secret_key, true, address_type, network);
					let private_key = PrivateKey::new(secret_key, network);
					let hash = private_key.public_key(&SECP).pubkey_hash().to_byte_array();
					let matches = |prefix: String| {
						let matcher = PrefixMatcher::new(
							&[prefix], case_sensitive, address_type, network,
						);
						let matcher = match matcher {
							Ok(matcher) => matcher,
							Err(_) => return false,
						};
						if address_type == VanityAddressType::P2tr {
							let program = addr.witness_program().unwrap();
							let output_key = program.program().as_bytes().try_into().unwrap();
							assert!(!matcher.matches(&hash));
							matcher.matches_output_key(&output_key)
						} else {
							assert!(!matcher.matches_output_key(&[0u8; 32]));
							matcher.matches(&hash)
						}
					};
					let addr = addr.to_string();
					let len = len.min(addr.len());

					let prefix = if case_sensitive {
						addr[..len].to_string()
					} else {
						addr[..len].to_uppercase()
					};
					assert!(matches(prefix));

					// Change the last character of the prefix, it should not match anymore.
					// The end of a Base58 address is the checksum, which the matcher
					// does not look at.
					if len < 6 || (is_p2pkh && len > 20) {
						continue;
					}
					let last = if addr[len - 1..len].eq_ignore_ascii_case("q") { "p" } else { "q" };
					let prefix = format!("{}{}", &addr[..len - 1], last);
					assert!(!matches(prefix));
				}
			}
		}
	}

	#[test]
	fn taproot_matcher_agrees_with_address() {
		let mut keys = KeyWalker::new(true, true);
		let batch_len = keys.next_batch();

		// Short prefixes, so a lot of the addresses match.
		let prefixes = ["bc1p", "bc1pq", "BC1P5", "bc1pl", "bc1pqq", "bc1pb"];
		let mut matches = 0;
		for prefix in prefixes.iter() {
			let matcher = PrefixMatcher::new(
				&[prefix.to_string()], false, VanityAddressType::P2tr, Network::Bitcoin,
			);
			let matcher = match matcher {
				Ok(matcher) => matcher,
				Err(_) => {
					assert_eq!(*prefix, "bc1pb");
					continue;
				},
			};
			for index in 0..batch_len {
				let output_key = keys.output_key(index);
				let secret_key = keys.secret_keys(index)[0];
				let addr = address(secret_key, true, VanityAddressType::P2tr, Network::Bitcoin);
				let expected = addr.to_string().starts_with(&prefix.to_lowercase());
				assert_eq!(matcher.matches_output_key(&output_key), expected, "{}", prefix);
				matches += usize::from(expected);
			}
		}
		assert!(matches > batch_len);
	}

	#[test]
	fn base58_ranges_agree_with_slow_matcher() {
		let mut keys = KeyWalker::new(true, false);
		let batch_len = keys.next_batch();

		// Short prefixes, so a lot of the addresses match.
		let cases = [
			(Network::Bitcoin, &["1", "11", "1a", "1B", "1c2", "12", "1Q", "1z"][..]),
			(Network::Testnet, &["m", "n", "mz", "N", "n2", "mZ", "nZ"][..]),
		];
		for (network, prefixes) in cases.iter() {
			let version = p2pkh_version(*network);
			for case_sensitive in [true, false].iter().copied() {
				let mut matches = 0;
				for prefix in prefixes.iter() {
					let prefixes = [prefix.to_string()];
					let address_type = VanityAddressType::P2pkh;
					let matcher = PrefixMatcher::new(&prefixes, case_sensitive, address_type, *network);
					let matcher = match matcher {
						Ok(matcher) => matcher,
						// Prefixes that no address can start with.
						Err(_) => {
							assert!(["N", "mZ", "nZ"].contains(prefix));
							assert!(case_sensitive || *prefix == "nZ");
							continue;
						},
					};
					match matcher {
						PrefixMatcher::Base58(_) => {},
						_ => panic!("not the fast matcher"),
					}

					for index in 0..batch_len {
						for hash in keys.pubkey_hashes(index).iter() {
							let mut payload = [0u8; 21];
							payload[0] = version;
							payload[1..].copy_from_slice(hash);
							let addr = bitcoin::base58::encode_check(&payload);
							let expected = if case_sensitive {
								addr.starts_with(prefix)
							} else {
								addr.to_lowercase().starts_with(&prefix.to_lowercase())
							};
							assert_eq!(matcher.matches(hash), expected, "{} {}", prefix, addr);
							matches += usize::from(expected);
						}
					}
				}
				assert!(matches > batch_len);
			}
		}
	}

	#[test]
	fn search_finds_address() {
		for (prefix, network) in [
			("1a", Network::Bitcoin),
			("mz", Network::Testnet),
			("bc1qqq", Network::Bitcoin),
			("tb1pqq", Network::Testnet),
			("bcrt1qq", Network::Regtest),
		].iter() {
			let search = VanitySearch::new(vec![prefix.to_string()], false, true, None).unwrap();
			assert_eq!(search.network(), *network);
			let mut found = Vec::new();
			search.search(2, |m| {
				found.push(m);
				found.len() < 3
			});
			assert_eq!(found.len(), 3);
			for m in found {
				let addr = m.address.to_string();
				assert!(addr.to_lowercase().starts_with(&prefix.to_lowercase()), "{}", addr);
				assert_eq!(addr, address(m.private_key.inner, true, search.address_type, *network).to_string());
				assert!(m.attempts > 0);
			}
		}
	}

	#[test]
	fn search_finds_raw_taproot_address() {
		let search = VanitySearch::new(vec!["bc1pqq".to_owned()], false, true, None)
			.unwrap().with_raw_taproot().unwrap();
		let mut found = Vec::new();
		search.search(2, |m| {
			found.push(m);
			found.len() < 3
		});
		assert_eq!(found.len(), 3);
		for m in found {
			let addr = m.address.to_string();
			assert!(addr.starts_with("bc1pqq"), "{}", addr);
			let expected = search_address(
				m.private_key.inner, true, true, VanityAddressType::P2tr, Network::Bitcoin,
			);
			assert_eq!(addr, expected.to_string());
			// The output key is the public key itself.
			let (key, _) = m.private_key.inner.x_only_public_key(&SECP);
			assert_eq!(m.address.witness_program().unwrap().program().as_bytes(), key.serialize());
		}
	}
}
