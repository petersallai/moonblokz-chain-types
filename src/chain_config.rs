/*! Zero-copy view and builder for the chain-config block payload envelope.

A `PAYLOAD_TYPE_CHAIN_CONFIG` payload is framed as:

```text
config_value_count : u16                        (2 B, little-endian)
config_values      : config_value_count × {
                         key_byte     : u8
                         value_length : u8
                         value        : value_length bytes
                     }
content_signature  : [u8; SIGNATURE_SIZE]       (node #0, over the content region)
```

The **content region** is the count field plus every entry. Its end is
*derived* by walking the entries, never read from a fixed offset — that is what
makes truncation and trailing padding detectable, and the content region is the
canonical byte sequence node #0 signs (FR7), so the framing rules here are
permanent wire format.

# Why the envelope lives here and the semantics do not

The FR7 content-signature check is an FR9 Tier-1 trust-anchor check: it runs on
every chain-config block at intake, irrespective of the FR8 tentative-vs-durable
state. Tier 1 is state-free and must not consult the configuration module, so
the content/signature boundary has to be findable *before* any configuration
involvement — which puts the envelope in this crate, beside the transaction and
balance payload views.

The complement holds too: nothing here interprets a parameter identifier. The
key byte's *form flag* and *identifier range* are framing, so they are checked
here; what an identifier means, how wide its value must be and whether its value
may be a program are registry questions owned by `moonblokz-configuration`
(FR56).
*/

use crate::error::BlockError;
use moonblokz_crypto::{CryptoTrait, SignatureTrait};

use crate::block::MAX_PAYLOAD_SIZE;

/// Size of the `config_value_count` field in bytes.
pub const CONFIG_VALUE_COUNT_SIZE: usize = 2;

/// Bit 7 of a key byte: set selects a bytecode value, clear a literal value.
pub const CONFIG_KEY_BYTECODE_FLAG: u8 = 0x80;

/// Highest usable parameter identifier.
///
/// Identifier `127` is permanently unallocated because its bytecode form
/// (`0x7F | 0x80`) would be `0xFF`, the reserved multi-byte-key escape. The
/// usable range is therefore `1..=126`, and the four key bytes `0x00`, `0x7F`,
/// `0x80` and `0xFF` are all malformed.
pub const CONFIG_PARAMETER_ID_MAX: u8 = 126;

/// Extracts the parameter identifier carried by a key byte.
const fn parameter_id_of(key_byte: u8) -> u8 {
    key_byte & !CONFIG_KEY_BYTECODE_FLAG
}

/// Whether a key byte names a parameter identifier inside the usable range.
const fn is_valid_key_byte(key_byte: u8) -> bool {
    let id = parameter_id_of(key_byte);
    id != 0 && id <= CONFIG_PARAMETER_ID_MAX
}

// =======================================================================
// View types
// =======================================================================

/// Zero-copy view over a chain-config block payload.
///
/// `Debug`, `Clone`, and `PartialEq` are intentionally omitted to minimise
/// binary size on embedded targets.
pub struct ChainConfigBlockPayloadView<'a> {
    payload: &'a [u8],
    /// Derived by the constructor's entry walk, not read from the payload.
    content_len: usize,
}

impl<'a> ChainConfigBlockPayloadView<'a> {
    /// Validates the envelope framing and returns a borrowed view over it.
    ///
    /// Returns `None` when the payload is malformed: shorter than
    /// `CONFIG_VALUE_COUNT_SIZE + SIGNATURE_SIZE`, a `value_length` running past
    /// the end, `content_end + SIGNATURE_SIZE != payload.len()` (trailing or
    /// missing bytes), a parameter identifier appearing twice in either value
    /// form, or a key byte outside the usable identifier range.
    ///
    /// Public — unlike the transaction and balance payload views, which are only
    /// ever reached through a block — because the configuration module retains a
    /// bare payload and re-reads its entries without a block around it.
    pub fn from_payload(payload: &'a [u8]) -> Option<Self> {
        if payload.len() < CONFIG_VALUE_COUNT_SIZE + moonblokz_crypto::SIGNATURE_SIZE {
            return None;
        }

        let count = u16::from_le_bytes([payload[0], payload[1]]);
        // One bit per usable identifier (1..=126): a duplicate in either value
        // form is malformed, so the flag bit is masked off before the test.
        let mut seen: u128 = 0;
        let mut offset = CONFIG_VALUE_COUNT_SIZE;

        for _ in 0..count {
            if offset + 2 > payload.len() {
                return None;
            }
            let key_byte = payload[offset];
            if !is_valid_key_byte(key_byte) {
                return None;
            }
            let id_bit = 1u128 << parameter_id_of(key_byte);
            if seen & id_bit != 0 {
                return None;
            }
            seen |= id_bit;

            offset += 2 + payload[offset + 1] as usize;
            if offset > payload.len() {
                return None;
            }
        }

        // `content_end` is where the walk stopped. Anything else in the payload
        // must be exactly the signature: a shorter or longer remainder is
        // truncation or padding, and both change the signed byte sequence.
        if offset + moonblokz_crypto::SIGNATURE_SIZE != payload.len() {
            return None;
        }

        Some(Self {
            payload,
            content_len: offset,
        })
    }

    /// Returns the content region — the canonical bytes node #0 signs (FR7).
    pub fn content(&self) -> &'a [u8] {
        &self.payload[..self.content_len]
    }

    /// Returns the node-#0 content signature trailing the content region.
    pub fn content_signature(&self) -> &'a [u8] {
        &self.payload[self.content_len..]
    }

    /// Number of configuration entries the content declares.
    pub fn count(&self) -> u16 {
        u16::from_le_bytes([self.payload[0], self.payload[1]])
    }

    /// Returns an iterator over the configuration entries.
    pub fn iter(&self) -> ConfigValueIterator<'a> {
        ConfigValueIterator {
            content: self.content(),
            offset: CONFIG_VALUE_COUNT_SIZE,
            remaining: self.count(),
        }
    }
}

/// Zero-copy iterator over the entries of a chain-config content region.
pub struct ConfigValueIterator<'a> {
    content: &'a [u8],
    offset: usize,
    remaining: u16,
}

impl<'a> Iterator for ConfigValueIterator<'a> {
    type Item = ConfigValueView<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }
        if self.offset + 2 > self.content.len() {
            return None;
        }
        let key_byte = self.content[self.offset];
        let value_start = self.offset + 2;
        let value_end = value_start + self.content[self.offset + 1] as usize;
        if value_end > self.content.len() {
            return None;
        }
        self.offset = value_end;
        self.remaining -= 1;
        Some(ConfigValueView {
            key_byte,
            value: &self.content[value_start..value_end],
        })
    }
}

/// Zero-copy view of a single configuration entry.
pub struct ConfigValueView<'a> {
    key_byte: u8,
    value: &'a [u8],
}

impl<'a> ConfigValueView<'a> {
    /// The raw key byte, as written. Carried so that a registry-level rejection
    /// can name the offending byte in its log record.
    pub fn key_byte(&self) -> u8 {
        self.key_byte
    }

    /// Parameter identifier, in `1..=CONFIG_PARAMETER_ID_MAX`.
    pub fn parameter_id(&self) -> u8 {
        parameter_id_of(self.key_byte)
    }

    /// Whether the value is a bytecode program rather than a literal.
    pub fn is_bytecode(&self) -> bool {
        self.key_byte & CONFIG_KEY_BYTECODE_FLAG != 0
    }

    /// The value bytes, `value_length` long.
    pub fn value(&self) -> &'a [u8] {
        self.value
    }
}

// =======================================================================
// Builder types
// =======================================================================

/// Frames a chain-config override set and appends its node-#0 signature.
///
/// The framed payload is handed to
/// [`BlockBuilder::set_chain_config_payload`](crate::BlockBuilder::set_chain_config_payload)
/// verbatim.
pub struct ChainConfigPayloadBuilder {
    payload: [u8; MAX_PAYLOAD_SIZE],
    content_len: usize,
    count: u16,
    seen: u128,
}

impl ChainConfigPayloadBuilder {
    /// Creates a builder holding an empty override set.
    ///
    /// An empty set is valid content: it resolves every parameter to its
    /// code-baked default.
    //
    // `Default` is intentionally not implemented, matching `BlockBuilder`.
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self {
            payload: [0u8; MAX_PAYLOAD_SIZE],
            content_len: CONFIG_VALUE_COUNT_SIZE,
            count: 0,
            seen: 0,
        }
    }

    /// Appends a literal-valued entry.
    ///
    /// The value bytes are written verbatim; whether their length matches the
    /// parameter's declared width is a registry question, checked by
    /// `moonblokz-configuration`.
    pub fn add_literal(&mut self, parameter_id: u8, value: &[u8]) -> Result<&mut Self, BlockError> {
        self.add_entry(parameter_id, false, value)
    }

    /// Appends a bytecode-valued entry.
    pub fn add_bytecode(
        &mut self,
        parameter_id: u8,
        program: &[u8],
    ) -> Result<&mut Self, BlockError> {
        self.add_entry(parameter_id, true, program)
    }

    /// The value form is a separate argument rather than bit 7 of `parameter_id`,
    /// and `parameter_id` is range-checked *before* any masking. Validating the
    /// masked byte instead would accept `add_literal(129, …)` — identifier 1 with
    /// the flag bit set — and frame it as a **bytecode** entry the caller never
    /// asked for, permanently, under a signature.
    fn add_entry(
        &mut self,
        parameter_id: u8,
        bytecode: bool,
        value: &[u8],
    ) -> Result<&mut Self, BlockError> {
        if parameter_id == 0 || parameter_id > CONFIG_PARAMETER_ID_MAX {
            return Err(BlockError::MalformedBlock(
                "chain-config parameter identifier out of range",
            ));
        }
        let key_byte = if bytecode {
            parameter_id | CONFIG_KEY_BYTECODE_FLAG
        } else {
            parameter_id
        };
        let id_bit = 1u128 << parameter_id;
        if self.seen & id_bit != 0 {
            return Err(BlockError::MalformedBlock(
                "duplicate chain-config parameter identifier",
            ));
        }
        // `value_length` is one byte, so this is the framing's own ceiling.
        if value.len() > u8::MAX as usize {
            return Err(BlockError::MalformedBlock("chain-config value too long"));
        }

        let content_end = self.content_len + 2 + value.len();
        let payload_len = content_end + moonblokz_crypto::SIGNATURE_SIZE;
        if payload_len > MAX_PAYLOAD_SIZE {
            return Err(BlockError::PayloadTooLarge {
                max: MAX_PAYLOAD_SIZE,
                actual: payload_len,
            });
        }

        self.payload[self.content_len] = key_byte;
        self.payload[self.content_len + 1] = value.len() as u8;
        self.payload[self.content_len + 2..content_end].copy_from_slice(value);
        self.content_len = content_end;
        self.count += 1;
        self.payload[0..CONFIG_VALUE_COUNT_SIZE].copy_from_slice(&self.count.to_le_bytes());
        self.seen |= id_bit;
        Ok(self)
    }

    /// Returns the content region framed so far — what the signature covers.
    pub fn content(&self) -> &[u8] {
        &self.payload[..self.content_len]
    }

    /// Signs the content region with node #0's key and returns the full payload.
    ///
    /// Takes `&mut self` rather than consuming the builder because the result is
    /// a slice of the builder's own buffer; the call writes only the signature
    /// trailer, so repeating it is harmless.
    pub fn build_signed<Crypto: CryptoTrait>(&mut self, crypto: &Crypto) -> &[u8] {
        let signature = crypto.sign(&self.payload[..self.content_len]);
        let payload_len = self.content_len + moonblokz_crypto::SIGNATURE_SIZE;
        self.payload[self.content_len..payload_len].copy_from_slice(signature.serialize());
        &self.payload[..payload_len]
    }
}

// =======================================================================
// Tests
// =======================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::{Block, BlockBuilder, BlockHeader, PAYLOAD_TYPE_CHAIN_CONFIG};
    use moonblokz_crypto::{Crypto, PRIVATE_KEY_SIZE, SIGNATURE_SIZE, Signature};

    fn test_crypto() -> Crypto {
        Crypto::new([1u8; PRIVATE_KEY_SIZE])
            .ok()
            .expect("test private key should be accepted")
    }

    fn sample_header() -> BlockHeader {
        BlockHeader {
            version: 1,
            sequence: 1,
            creator: 0,
            mined_amount: 0,
            payload_type: PAYLOAD_TYPE_CHAIN_CONFIG,
            consumed_votes: 0,
            first_voted_node: 0,
            consumed_votes_from_first_voted_node: 0,
            previous_hash: [0; 32],
            signature: [0; 64],
        }
    }

    /// Builds a chain-config block around a raw payload, bypassing the payload
    /// builder so that malformed framing can be exercised.
    fn block_with_payload(payload: &[u8]) -> Block {
        let mut builder = BlockBuilder::new().header(sample_header());
        builder.set_chain_config_payload(payload).unwrap();
        builder.build_signed(&test_crypto()).unwrap()
    }

    fn signed_payload_bytes(builder: &mut ChainConfigPayloadBuilder) -> [u8; MAX_PAYLOAD_SIZE] {
        let mut bytes = [0u8; MAX_PAYLOAD_SIZE];
        let signed = builder.build_signed(&test_crypto());
        bytes[..signed.len()].copy_from_slice(signed);
        bytes
    }

    // -- Round trip --

    #[test]
    fn builder_view_round_trip() {
        let mut builder = ChainConfigPayloadBuilder::new();
        builder.add_literal(1, &60_000u64.to_le_bytes()).unwrap();
        builder.add_bytecode(2, &[0x70, 0x01, 0x00, 0x01]).unwrap();
        let content_len = builder.content().len();
        let signed = builder.build_signed(&test_crypto());

        let block = block_with_payload(signed);
        let view = block.view().chain_config().unwrap();

        assert_eq!(view.count(), 2);
        assert_eq!(view.content().len(), content_len);
        assert_eq!(view.content_signature().len(), SIGNATURE_SIZE);

        let mut iter = view.iter();
        let first = iter.next().unwrap();
        assert_eq!(first.key_byte(), 0x01);
        assert_eq!(first.parameter_id(), 1);
        assert!(!first.is_bytecode());
        assert_eq!(first.value(), &60_000u64.to_le_bytes());

        let second = iter.next().unwrap();
        assert_eq!(second.key_byte(), 0x82);
        assert_eq!(second.parameter_id(), 2);
        assert!(second.is_bytecode());
        assert_eq!(second.value(), &[0x70, 0x01, 0x00, 0x01]);

        assert!(iter.next().is_none());
    }

    #[test]
    fn content_signature_verifies_over_the_content_region() {
        let crypto = test_crypto();
        let mut builder = ChainConfigPayloadBuilder::new();
        builder.add_literal(10, &[3]).unwrap();
        let signed = builder.build_signed(&crypto);

        let block = block_with_payload(signed);
        let view = block.view().chain_config().unwrap();

        let signature = Signature::new(view.content_signature())
            .ok()
            .expect("builder-produced signature should deserialize");
        assert!(crypto.verify_signature(view.content(), &signature, crypto.public_key()));
    }

    #[test]
    fn empty_override_set_is_valid_content() {
        let mut builder = ChainConfigPayloadBuilder::new();
        let signed = builder.build_signed(&test_crypto());
        assert_eq!(signed.len(), CONFIG_VALUE_COUNT_SIZE + SIGNATURE_SIZE);

        let block = block_with_payload(signed);
        let view = block.view().chain_config().unwrap();
        assert_eq!(view.count(), 0);
        assert_eq!(view.content().len(), CONFIG_VALUE_COUNT_SIZE);
        assert!(view.iter().next().is_none());
    }

    #[test]
    fn wrong_payload_type_returns_none() {
        let header = BlockHeader {
            payload_type: 0,
            ..sample_header()
        };
        let block = BlockBuilder::new()
            .header(header)
            .build_signed(&test_crypto())
            .unwrap();
        assert!(block.view().chain_config().is_none());
    }

    // -- Malformed framing --

    #[test]
    fn payload_shorter_than_count_and_signature_is_malformed() {
        // One byte short of the minimum, and otherwise well formed: `count == 0`
        // means the walk stops immediately at `content_end == 2`, so only the
        // length guard can reject this.
        let short = [0u8; CONFIG_VALUE_COUNT_SIZE + SIGNATURE_SIZE - 1];
        let block = block_with_payload(&short);
        assert!(block.view().chain_config().is_none());

        // The minimum itself is accepted, which is what makes the guard's boundary
        // the tested property rather than its direction.
        let minimum = [0u8; CONFIG_VALUE_COUNT_SIZE + SIGNATURE_SIZE];
        let block = block_with_payload(&minimum);
        assert!(block.view().chain_config().is_some());
    }

    #[test]
    fn value_length_running_past_the_end_is_malformed() {
        let mut builder = ChainConfigPayloadBuilder::new();
        builder.add_literal(1, &[0u8; 8]).unwrap();
        let mut bytes = signed_payload_bytes(&mut builder);
        let payload_len = CONFIG_VALUE_COUNT_SIZE + 2 + 8 + SIGNATURE_SIZE;
        // Entry `value_length` sits directly after the entry's key byte.
        bytes[CONFIG_VALUE_COUNT_SIZE + 1] = 200;

        let block = block_with_payload(&bytes[..payload_len]);
        assert!(block.view().chain_config().is_none());
    }

    #[test]
    fn trailing_byte_makes_the_content_end_mismatch() {
        let mut builder = ChainConfigPayloadBuilder::new();
        builder.add_literal(1, &[0u8; 8]).unwrap();
        let bytes = signed_payload_bytes(&mut builder);
        let payload_len = CONFIG_VALUE_COUNT_SIZE + 2 + 8 + SIGNATURE_SIZE;

        // One byte of padding past the signature: the content region is intact,
        // the derived end no longer accounts for the whole payload.
        let block = block_with_payload(&bytes[..payload_len + 1]);
        assert!(block.view().chain_config().is_none());

        // ... and one byte short of the signature.
        let block = block_with_payload(&bytes[..payload_len - 1]);
        assert!(block.view().chain_config().is_none());
    }

    #[test]
    fn duplicate_parameter_identifier_is_malformed() {
        // Two entries for identifier 1, the second in bytecode form: the flag
        // bit does not make it a different parameter.
        let mut payload = [0u8; CONFIG_VALUE_COUNT_SIZE + 3 + 3 + SIGNATURE_SIZE];
        payload[0..2].copy_from_slice(&2u16.to_le_bytes());
        payload[2] = 0x01;
        payload[3] = 1;
        payload[4] = 7;
        payload[5] = 0x81;
        payload[6] = 1;
        payload[7] = 7;

        let block = block_with_payload(&payload);
        assert!(block.view().chain_config().is_none());
    }

    #[test]
    fn invalid_key_bytes_are_malformed() {
        for key_byte in [0x00u8, 0x7F, 0x80, 0xFF] {
            let mut payload = [0u8; CONFIG_VALUE_COUNT_SIZE + 3 + SIGNATURE_SIZE];
            payload[0..2].copy_from_slice(&1u16.to_le_bytes());
            payload[2] = key_byte;
            payload[3] = 1;
            payload[4] = 42;

            let block = block_with_payload(&payload);
            assert!(
                block.view().chain_config().is_none(),
                "key byte {key_byte:#04X} must be rejected"
            );
        }
    }

    #[test]
    fn declared_count_beyond_the_entries_is_malformed() {
        // Two entries declared, one written, and the tail is a *valid* second key
        // byte followed by the signature region — so the walk cannot fail on the
        // key byte and has to fail on the bound. (A zero-filled tail would be
        // rejected by the key-byte check instead, leaving the bound untested.)
        let mut payload = [0u8; CONFIG_VALUE_COUNT_SIZE + 3 + SIGNATURE_SIZE];
        payload[0..2].copy_from_slice(&2u16.to_le_bytes());
        payload[2] = 0x01;
        payload[3] = 1;
        payload[4] = 42;
        payload[5] = 0x02;
        payload[6] = SIGNATURE_SIZE as u8;

        let block = block_with_payload(&payload);
        assert!(block.view().chain_config().is_none());
    }

    #[test]
    fn a_count_that_runs_the_walk_past_the_payload_is_malformed() {
        // The declared count is larger than any number of entries the payload
        // could hold, so the walk exhausts the buffer mid-entry.
        let mut payload = [0u8; CONFIG_VALUE_COUNT_SIZE + 3 + SIGNATURE_SIZE];
        payload[0..2].copy_from_slice(&u16::MAX.to_le_bytes());
        payload[2] = 0x01;
        payload[3] = 1;
        payload[4] = 42;

        let block = block_with_payload(&payload);
        assert!(block.view().chain_config().is_none());
    }

    // -- Builder rejections --

    #[test]
    fn builder_rejects_unusable_parameter_identifiers() {
        let mut builder = ChainConfigPayloadBuilder::new();
        assert!(builder.add_literal(0, &[1]).is_err());
        assert!(builder.add_literal(127, &[1]).is_err());
        assert!(builder.add_bytecode(127, &[1]).is_err());
        assert_eq!(builder.content().len(), CONFIG_VALUE_COUNT_SIZE);
    }

    #[test]
    fn builder_rejects_a_parameter_id_carrying_the_form_flag() {
        // The whole `0x80..=0xFF` input class: were the identifier range-checked
        // after masking, `add_literal(129, ..)` would frame identifier 1 as
        // *bytecode* — a value form the caller never asked for, signed into the
        // chain. Nothing downstream could tell it from an intentional program.
        let mut builder = ChainConfigPayloadBuilder::new();
        for parameter_id in 0x80u8..=0xFF {
            assert!(
                builder.add_literal(parameter_id, &[1]).is_err(),
                "add_literal({parameter_id:#04X}) must be refused"
            );
            assert!(
                builder.add_bytecode(parameter_id, &[1]).is_err(),
                "add_bytecode({parameter_id:#04X}) must be refused"
            );
        }
        assert_eq!(builder.content().len(), CONFIG_VALUE_COUNT_SIZE);
    }

    #[test]
    fn builder_rejects_duplicate_identifier_in_either_form() {
        let mut builder = ChainConfigPayloadBuilder::new();
        builder.add_literal(1, &[1]).unwrap();
        assert!(builder.add_literal(1, &[2]).is_err());
        assert!(builder.add_bytecode(1, &[2]).is_err());
    }

    #[test]
    fn builder_rejects_a_value_longer_than_the_length_field() {
        let mut builder = ChainConfigPayloadBuilder::new();
        let oversized = [0u8; 256];
        assert!(builder.add_literal(1, &oversized).is_err());
    }

    #[test]
    fn builder_reserves_room_for_the_signature() {
        let mut builder = ChainConfigPayloadBuilder::new();
        let chunk = [0u8; 255];
        let mut identifier = 1u8;
        // Fill until the framing refuses, then assert the refusal came from the
        // capacity check with the signature accounted for.
        while builder.add_literal(identifier, &chunk).is_ok() {
            identifier += 1;
        }
        let signed_len = builder.content().len() + SIGNATURE_SIZE;
        assert!(signed_len <= MAX_PAYLOAD_SIZE);
        assert!(signed_len + 2 + chunk.len() > MAX_PAYLOAD_SIZE);
    }
}
