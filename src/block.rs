/*! Block type and builder for MoonBlokz chain types.

This module provides three forms of a block per the Owned/View/Builder triplet
(FR61, AR7):

- [`Block`] — owned immutable block with internal fixed-size byte storage (~2 KB).
- [`BlockView`] — borrowed zero-copy view onto a `&[u8]` slice (~16 B: pointer + len).
- [`BlockBuilder`] — validated construction into an owned `Block`.

`Block` and `BlockView` expose identical read accessors; on `Block` they
delegate to a `BlockView` borrowed from the owned buffer, so the byte-offset
logic lives in exactly one place.

Block versioning invariant:
- `version == 0` is reserved for storage empty-slot markers.
- Valid MoonBlokz blocks must use a non-zero version value.

# Design note — embedded target

This is an embedded (`no_std`) library optimised for minimal binary size.
Trait implementations such as `Debug`, `Display`, `Clone`, and `PartialEq`
are intentionally omitted from public types to avoid pulling formatting
machinery and extra code into the final binary. Derive them downstream
via newtype wrappers if needed for diagnostics or testing.
*/

use crate::balance::{
    BALANCE_HEADER_SIZE, BALANCE_MAX_NODE_ID_OFFSET, BalanceBlockPayloadView, NodeInfo,
};
use crate::chain_config::ChainConfigBlockPayloadView;
use crate::error::BlockError;
use crate::hash::{HASH_SIZE, calculate_hash};
use crate::transaction::{
    ComplexTransaction, NodeTransfer, Registration, TransactionBlockPayloadView,
};
use moonblokz_crypto::{
    AGGREGATED_SIGNATURE_CONSTANT_SIZE, AGGREGATED_SIGNATURE_VARIABLE_SIZE, CryptoTrait,
    MAX_AGGREGATED_SIGNATURES, SIGNATURE_SIZE, SignatureTrait,
};

/// This build's block capacity in bytes: the largest encoded block it can
/// frame, hold and store.
///
/// A build parameter, selected by the block-size tier feature (DEC-220), not a
/// protocol constant. The chain's own maximum is configuration ID 3
/// `block_size_limit`; acceptance refuses a chain that declares more than this
/// capacity, so a block above it is a local refusal, never evidence (DEC-225).
#[cfg(feature = "block-size-2016")]
pub const MAX_BLOCK_SIZE: usize = 2016;
/// This build's block capacity in bytes (the `block-size-65536` tier, the first
/// above `u16`; see the `block-size-2016` documentation).
#[cfg(feature = "block-size-65536")]
pub const MAX_BLOCK_SIZE: usize = 65536;

// Every capacity and every block length the stack holds is a `u32` (DEC-224,
// DEC-227), so a tier above it could not be stated.
const _: () = assert!(MAX_BLOCK_SIZE <= u32::MAX as usize);

/// Header size in bytes: 58 fixed bytes, then the block signature, whose size is the
/// build's scheme's (DEC-251): 122 (`schnorr`), 106 (`bls-min-sig`), 154 (`bls-min-pk`).
pub const HEADER_SIZE: usize = SIGNATURE_OFFSET + SIGNATURE_SIZE;

const VERSION_OFFSET: usize = 0;
const SEQUENCE_OFFSET: usize = 1;
const CREATOR_OFFSET: usize = 5;
const MINED_AMOUNT_OFFSET: usize = 9;
const PAYLOAD_TYPE_OFFSET: usize = 13;
const CONSUMED_VOTES_OFFSET: usize = 14;
const FIRST_VOTED_NODE_OFFSET: usize = 18;
const CONSUMED_VOTES_FROM_FIRST_OFFSET: usize = 22;
const PREVIOUS_HASH_OFFSET: usize = 26;
const SIGNATURE_OFFSET: usize = 58;
const PAYLOAD_OFFSET: usize = HEADER_SIZE;

// Compile-time layout invariants: accessors below assume these hold once
// `from_bytes` has guaranteed `bytes.len() >= HEADER_SIZE`. Reordering the
// offset constants without rechecking the asserts will fail to compile.
const _: () = assert!(VERSION_OFFSET < HEADER_SIZE);
const _: () = assert!(SIGNATURE_OFFSET + SIGNATURE_SIZE == HEADER_SIZE);
const _: () = assert!(PREVIOUS_HASH_OFFSET + 32 == SIGNATURE_OFFSET);
const _: () = assert!(PAYLOAD_OFFSET == HEADER_SIZE);

/// Length of the block-creator signature preimage (FR70, DEC-272): the header bytes
/// before the signature field followed by the SHA-256 hash of the payload — 90 bytes
/// under every signature scheme, since the signature is the header's last field.
const SIGNING_PREIMAGE_SIZE: usize = SIGNATURE_OFFSET + HASH_SIZE;

// Domain separation is by message form (DEC-248): the preimage starts with the
// version byte. A node transfer is the one fixed-size signed transaction whose
// type byte (1) equals the block version (1), so the two must differ in length.
const _: () = assert!(SIGNING_PREIMAGE_SIZE != crate::transaction::NODE_TRANSFER_SIZE);
// `build_signed` writes the payload hash into the signature field to sign.
const _: () = assert!(SIGNING_PREIMAGE_SIZE <= HEADER_SIZE);

/// Maximum payload bytes that can fit in a block.
pub const MAX_PAYLOAD_SIZE: usize = MAX_BLOCK_SIZE - HEADER_SIZE;

/// Payload type: transaction block.
pub const PAYLOAD_TYPE_TRANSACTION: u8 = 1;
/// Payload type: balance block.
pub const PAYLOAD_TYPE_BALANCE: u8 = 2;
/// Payload type: chain configuration block.
pub const PAYLOAD_TYPE_CHAIN_CONFIG: u8 = 3;
/// Payload type: approval (evidence) block.
pub const PAYLOAD_TYPE_APPROVAL: u8 = 4;
/// Payload type: twin fact block (FR70–FR72): the proof that the creator of the
/// branch's block at the proof's sequence signed a second child of the same parent.
pub const PAYLOAD_TYPE_TWIN_EVIDENCE: u8 = 5;

/// Parsed view of the fixed block header.
///
/// `Debug`, `Clone`, and `PartialEq` are intentionally omitted to minimise
/// binary size on embedded targets.
pub struct BlockHeader {
    /// Block version.
    ///
    /// `0` is reserved for storage empty-slot markers.
    /// Valid MoonBlokz blocks must use a non-zero version value.
    pub version: u8,
    /// Sequence number.
    pub sequence: u32,
    /// Creator node id.
    pub creator: u32,
    /// Mined amount.
    pub mined_amount: u32,
    /// Payload type discriminator.
    pub payload_type: u8,
    /// Consumed votes.
    pub consumed_votes: u32,
    /// First voted node id.
    pub first_voted_node: u32,
    /// Consumed votes from first voted node.
    pub consumed_votes_from_first_voted_node: u32,
    /// Previous block hash.
    pub previous_hash: [u8; 32],
    /// Block signature.
    pub signature: [u8; SIGNATURE_SIZE],
}

/// Borrowed zero-copy view onto a serialized block.
///
/// `BlockView<'a>` holds only a `&'a [u8]` reference (pointer + length, ~16 B),
/// providing zero-copy access to the canonical block bytes. Validate structural
/// invariants once via [`from_bytes`](Self::from_bytes); afterwards, the
/// accessors read directly from the borrowed slice on every call.
///
/// Construct a view from any byte slice — including the internal buffer of an
/// owned [`Block`] via [`Block::view`].
///
/// `Debug`, `Clone`, and `PartialEq` are intentionally omitted to minimise
/// binary size on embedded targets. `#[repr(transparent)]` pins the layout to
/// the documented "pointer + length" working set.
#[repr(transparent)]
pub struct BlockView<'a> {
    bytes: &'a [u8],
}

impl<'a> BlockView<'a> {
    /// Creates a borrowed view over encoded block bytes.
    ///
    /// Validates structural invariants (length within
    /// `[HEADER_SIZE, MAX_BLOCK_SIZE]` and non-zero version) **without copying**
    /// the input slice. The returned view borrows from `bytes`.
    ///
    /// Parameters:
    /// - `bytes`: encoded block bytes.
    ///
    /// Example:
    /// ```
    /// use moonblokz_chain_types::{BlockView, HEADER_SIZE};
    ///
    /// let mut bytes = [0u8; HEADER_SIZE];
    /// bytes[0] = 1;
    /// let view_result = BlockView::from_bytes(&bytes);
    /// assert!(view_result.is_ok());
    /// let view = match view_result {
    ///     Ok(value) => value,
    ///     Err(_) => return,
    /// };
    /// assert_eq!(view.len(), HEADER_SIZE);
    /// ```
    pub fn from_bytes(bytes: &'a [u8]) -> Result<Self, BlockError> {
        if bytes.len() < HEADER_SIZE {
            return Err(BlockError::InputTooSmall {
                min: HEADER_SIZE,
                actual: bytes.len(),
            });
        }
        if bytes.len() > MAX_BLOCK_SIZE {
            return Err(BlockError::InputTooLarge {
                max: MAX_BLOCK_SIZE,
                actual: bytes.len(),
            });
        }
        if bytes[VERSION_OFFSET] == 0 {
            return Err(BlockError::MalformedBlock("block version must be non-zero"));
        }
        Ok(Self { bytes })
    }

    /// Returns the canonical serialized bytes that this view borrows from.
    pub fn serialized_bytes(&self) -> &'a [u8] {
        self.bytes
    }

    /// Returns the canonical block hash.
    pub fn hash(&self) -> [u8; HASH_SIZE] {
        calculate_hash(self.bytes)
    }

    /// Returns the encoded length in bytes.
    //
    // A valid `BlockView` always spans at least `HEADER_SIZE` bytes, so it can
    // never be empty. An `is_empty()` method would be misleading.
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Block version. `0` is reserved for storage empty-slot markers.
    pub fn version(&self) -> u8 {
        self.bytes[VERSION_OFFSET]
    }

    /// Block sequence number.
    pub fn sequence(&self) -> u32 {
        read_u32_le(self.bytes, SEQUENCE_OFFSET)
    }

    /// Creator node id.
    pub fn creator(&self) -> u32 {
        read_u32_le(self.bytes, CREATOR_OFFSET)
    }

    /// Mined amount (excluding transaction fees).
    pub fn mined_amount(&self) -> u32 {
        read_u32_le(self.bytes, MINED_AMOUNT_OFFSET)
    }

    /// Payload type discriminator.
    pub fn payload_type(&self) -> u8 {
        self.bytes[PAYLOAD_TYPE_OFFSET]
    }

    /// Consumed votes.
    pub fn consumed_votes(&self) -> u32 {
        read_u32_le(self.bytes, CONSUMED_VOTES_OFFSET)
    }

    /// First voted node id.
    pub fn first_voted_node(&self) -> u32 {
        read_u32_le(self.bytes, FIRST_VOTED_NODE_OFFSET)
    }

    /// Consumed votes from first voted node.
    pub fn consumed_votes_from_first_voted_node(&self) -> u32 {
        read_u32_le(self.bytes, CONSUMED_VOTES_FROM_FIRST_OFFSET)
    }

    /// Previous block hash (32 bytes, borrowed).
    pub fn previous_hash(&self) -> &'a [u8] {
        &self.bytes[PREVIOUS_HASH_OFFSET..PREVIOUS_HASH_OFFSET + 32]
    }

    /// Block signature (`SIGNATURE_SIZE` bytes, borrowed).
    pub fn signature(&self) -> &'a [u8] {
        &self.bytes[SIGNATURE_OFFSET..HEADER_SIZE]
    }

    /// Returns the payload slice.
    pub fn payload(&self) -> &'a [u8] {
        &self.bytes[PAYLOAD_OFFSET..self.bytes.len()]
    }

    /// The bytes the block-creator signature signs (FR70, DEC-272): the header
    /// before the signature field followed by `H(payload)`, so a header plus its
    /// payload hash verifies the signature. The view's length is the payload's end,
    /// so a padded storage slot must be cut to the block's exact length first.
    pub fn signing_preimage(&self) -> [u8; SIGNING_PREIMAGE_SIZE] {
        signing_preimage_of(self.bytes, &calculate_hash(self.payload()))
    }

    /// Recovers the block's **exact** serialized byte length by walking its
    /// self-delimiting payload structurally.
    ///
    /// This is not [`Self::len`]. `len()` reports how long the borrowed slice
    /// is; `content_length()` reports how long the block actually is. The two
    /// agree for a block parsed from its wire bytes and diverge for one read
    /// back from durable storage, which arrives zero-padded to a fixed slot
    /// with no recorded length. Recovering the exact length is what lets a
    /// restarting node recompute the block hash and re-verify the creator
    /// signature over the bytes that were originally signed (FR59) — both are
    /// taken over `bytes[..content_length()]`, so a padded slice silently
    /// produces the wrong answer for each.
    ///
    /// The walk is **count-based and structural**, never a trailing-zero scan:
    /// a block's real content may legitimately end in zero bytes. It returns
    /// `None` rather than guessing whenever the payload does not frame
    /// coherently — an unknown payload type or transaction discriminant, a
    /// declared count that over-runs the buffer, or a computed length beyond
    /// the slice.
    ///
    /// `payload_type == 4` (approval evidence) is framed from its own fields
    /// (DEC-195, see [`ApprovalView`]); its bytes after the framed length are
    /// padding, as for every other type.
    pub fn content_length(&self) -> Option<usize> {
        let payload = self.payload();
        let payload_len = match self.payload_type() {
            PAYLOAD_TYPE_TRANSACTION => crate::transaction::payload_content_len(payload)?,
            PAYLOAD_TYPE_BALANCE => crate::balance::payload_content_len(payload)?,
            PAYLOAD_TYPE_CHAIN_CONFIG => {
                crate::chain_config::content_end(payload)?.checked_add(SIGNATURE_SIZE)?
            }
            PAYLOAD_TYPE_APPROVAL => approval_frame(payload)?.len,
            PAYLOAD_TYPE_TWIN_EVIDENCE => twin_frame(payload)?,
            _ => return None,
        };

        let total = HEADER_SIZE.checked_add(payload_len)?;
        if total > self.bytes.len() {
            return None;
        }
        Some(total)
    }

    /// Returns a transaction block payload view if `payload_type() == 1`.
    pub fn transactions(&self) -> Option<TransactionBlockPayloadView<'a>> {
        if self.bytes[PAYLOAD_TYPE_OFFSET] != PAYLOAD_TYPE_TRANSACTION {
            return None;
        }
        TransactionBlockPayloadView::new(self.payload())
    }

    /// Returns a balance block payload view if `payload_type() == 2`.
    pub fn balances(&self) -> Option<BalanceBlockPayloadView<'a>> {
        if self.bytes[PAYLOAD_TYPE_OFFSET] != PAYLOAD_TYPE_BALANCE {
            return None;
        }
        BalanceBlockPayloadView::new(self.payload())
    }

    /// Returns a chain-config block payload view if `payload_type() == 3` and the
    /// envelope framing is well formed.
    pub fn chain_config(&self) -> Option<ChainConfigBlockPayloadView<'a>> {
        if self.bytes[PAYLOAD_TYPE_OFFSET] != PAYLOAD_TYPE_CHAIN_CONFIG {
            return None;
        }
        ChainConfigBlockPayloadView::from_payload(self.payload())
    }
}

/// The FR70 preimage (DEC-272) of a header whose first `SIGNATURE_OFFSET` bytes are
/// `header` and whose payload hashes to `payload_hash`. The one statement of the
/// preimage: a block's own ([`BlockView::signing_preimage`]) and a twin proof's
/// ([`TwinEvidenceView::proof_signing_preimage`]).
fn signing_preimage_of(
    header: &[u8],
    payload_hash: &[u8; HASH_SIZE],
) -> [u8; SIGNING_PREIMAGE_SIZE] {
    let mut preimage = [0u8; SIGNING_PREIMAGE_SIZE];
    preimage[..SIGNATURE_OFFSET].copy_from_slice(&header[..SIGNATURE_OFFSET]);
    preimage[SIGNATURE_OFFSET..].copy_from_slice(payload_hash);
    preimage
}

/// Offset of the approval evidence's signer bitmap: the payload starts with
/// `supporter_vote_sum u64 ‖ deviation_sequence u32 ‖ m u8` (DEC-195).
pub const APPROVAL_PREFIX_SIZE: usize = 13;
/// Offset of the approval evidence's `supporter_vote_sum u64` (DEC-195, DEC-216).
pub const APPROVAL_SUPPORTER_VOTE_SUM_OFFSET: usize = 0;
/// Size of one approval late-node entry, `node_id u32 ‖ accumulated_vote u32`
/// (DEC-184, DEC-195).
pub const APPROVAL_LATE_ENTRY_SIZE: usize = 8;
/// Offset of the approval evidence's `deviation_sequence u32`; the
/// `supporter_vote_sum u64` precedes it at offset 0.
pub const APPROVAL_DEVIATION_SEQUENCE_OFFSET: usize = 8;
/// Offset of the approval evidence's subgroup size `m u8`.
pub const APPROVAL_M_OFFSET: usize = 12;
/// `late_count` is a `u16` (DEC-242): a protocol bound of 65 535 late entries.
/// It is the last field of [`approval_fixed_size`].
pub const APPROVAL_LATE_COUNT_SIZE: usize = 2;
/// The largest subgroup an evidence can name: `m = 2·r − 1` with
/// `r ≤ MAX_AGGREGATED_SIGNATURES` (ADR-015).
pub const APPROVAL_MAX_SUBGROUP: usize = 2 * MAX_AGGREGATED_SIGNATURES - 1;

// `m` and a subgroup rank travel as a `u8`.
const _: () = assert!(APPROVAL_MAX_SUBGROUP <= u8::MAX as usize);

/// Length of an approval evidence payload without its late entries, for a
/// subgroup of `m` and `n` signers: prefix, the `⌈m/8⌉ B` bitmap, the
/// aggregated signature and `late_count`. The late-count field is its last two
/// bytes. The one statement of the DEC-195 layout, shared by the framing and
/// the writer.
pub const fn approval_fixed_size(m: usize, n: usize) -> usize {
    APPROVAL_PREFIX_SIZE
        + m.div_ceil(8)
        + AGGREGATED_SIGNATURE_CONSTANT_SIZE
        + AGGREGATED_SIGNATURE_VARIABLE_SIZE * n
        + APPROVAL_LATE_COUNT_SIZE
}

/// Frames an approval evidence payload (DEC-195, little-endian):
/// `supporter_vote_sum u64 ‖ deviation_sequence u32 ‖ m u8 ‖ signer bitmap
/// (⌈m/8⌉ B) ‖ aggregated signature ‖ late_count u16 ‖ late entries
/// (node_id u32 ‖ accumulated_vote u32) × late_count`.
///
/// `n`, the bitmap's population count, sizes the aggregate. Bits at positions
/// `≥ m` are counted but not judged here (that is Tier 1's). `None` for an `m`
/// above `2·MAX_AGGREGATED_SIGNATURES − 1`, `n == 0`, `n` above
/// `MAX_AGGREGATED_SIGNATURES`, a Schnorr aggregate whose `count` is not `n`,
/// or a frame longer than `payload`. The one framing of the layout: both
/// [`BlockView::content_length`] and [`ApprovalView`] use it.
fn approval_frame(payload: &[u8]) -> Option<ApprovalFrame> {
    let m = usize::from(*payload.get(APPROVAL_M_OFFSET)?);
    if m > APPROVAL_MAX_SUBGROUP {
        return None;
    }
    let bitmap = payload.get(APPROVAL_PREFIX_SIZE..APPROVAL_PREFIX_SIZE + m.div_ceil(8))?;
    let n = bitmap
        .iter()
        .map(|byte| byte.count_ones() as usize)
        .sum::<usize>();
    if n == 0 || n > MAX_AGGREGATED_SIGNATURES {
        return None;
    }
    // Schnorr's aggregate leads with its big-endian signer count.
    #[cfg(feature = "schnorr")]
    {
        let at = APPROVAL_PREFIX_SIZE + bitmap.len();
        let count = payload.get(at..at + 2)?;
        if usize::from(u16::from_be_bytes([count[0], count[1]])) != n {
            return None;
        }
    }
    let fixed = approval_fixed_size(m, n);
    let late_count = payload.get(fixed - APPROVAL_LATE_COUNT_SIZE..fixed)?;
    let late_count = usize::from(u16::from_le_bytes([late_count[0], late_count[1]]));
    let len = fixed + APPROVAL_LATE_ENTRY_SIZE * late_count;
    (len <= payload.len()).then_some(ApprovalFrame { len, fixed, n })
}

/// What [`approval_frame`] measured: the framed length, the fixed part's
/// length (`approval_fixed_size(m, n)`) and the signer count `n`.
struct ApprovalFrame {
    len: usize,
    fixed: usize,
    n: usize,
}

/// Borrowed view of an approval evidence payload (`payload_type == 4`).
///
/// Framed like [`BlockView::content_length`]'s approval arm, padding-tolerant
/// (bytes after the framed length are not read). Story 6.6 reads the deviation
/// it approves; Story 6.7's Tier-3 check and FR21 value read the rest.
pub struct ApprovalView<'a> {
    bytes: &'a [u8],
    fixed: usize,
    n: usize,
}

impl<'a> ApprovalView<'a> {
    /// Frames `payload` as approval evidence; `None` when it does not frame.
    pub fn from_payload(payload: &'a [u8]) -> Option<Self> {
        let frame = approval_frame(payload)?;
        Some(Self {
            bytes: &payload[..frame.len],
            fixed: frame.fixed,
            n: frame.n,
        })
    }

    /// The sequence of the deviation block this evidence approves.
    pub fn deviation_sequence(&self) -> u32 {
        read_u32_le(self.bytes, APPROVAL_DEVIATION_SEQUENCE_OFFSET)
    }

    /// The claimed FR21 value, `B_k − cv(d)` (DEC-216); Tier 3 checks it.
    pub fn supporter_vote_sum(&self) -> u64 {
        read_u64_le(self.bytes, APPROVAL_SUPPORTER_VOTE_SUM_OFFSET)
    }

    /// The subgroup size `m` the evidence names.
    pub fn m(&self) -> u8 {
        self.bytes[APPROVAL_M_OFFSET]
    }

    /// The signer bitmap, `⌈m/8⌉` bytes: rank `j` is bit `j % 8` of byte `j / 8`
    /// (LSB-first, DEC-241). Bits at positions `≥ m` are not judged here.
    pub fn bitmap(&self) -> &'a [u8] {
        &self.bytes[APPROVAL_PREFIX_SIZE..APPROVAL_PREFIX_SIZE + usize::from(self.m()).div_ceil(8)]
    }

    /// The bitmap's population count, the number of signers.
    pub fn signer_count(&self) -> u32 {
        self.n as u32
    }

    /// The aggregated signature in the crypto library's serialization (signers
    /// in ascending rank order).
    pub fn aggregate(&self) -> &'a [u8] {
        let start = APPROVAL_PREFIX_SIZE + usize::from(self.m()).div_ceil(8);
        &self.bytes[start..self.fixed - APPROVAL_LATE_COUNT_SIZE]
    }

    /// The number of late-node entries (DEC-184, DEC-242).
    pub fn late_count(&self) -> u16 {
        let at = self.fixed - APPROVAL_LATE_COUNT_SIZE;
        u16::from_le_bytes([self.bytes[at], self.bytes[at + 1]])
    }

    /// Late entry `i` as `(node_id, accumulated_vote)`; `None` for
    /// `i ≥ late_count`.
    pub fn late_entry(&self, i: usize) -> Option<(u32, u32)> {
        if i >= usize::from(self.late_count()) {
            return None;
        }
        let at = self.fixed + APPROVAL_LATE_ENTRY_SIZE * i;
        Some((read_u32_le(self.bytes, at), read_u32_le(self.bytes, at + 4)))
    }
}

/// Offset of a twin fact block's `snapshot u32`, after the proof header and the
/// proof's payload hash.
const TWIN_SNAPSHOT_OFFSET: usize = HEADER_SIZE + HASH_SIZE;
/// Offset of a twin fact block's subgroup size `m u8`.
const TWIN_M_OFFSET: usize = TWIN_SNAPSHOT_OFFSET + 4;
/// Size of a twin fact block payload without members: a penalty-only block
/// (`m = 0`). 159 / 143 / 191 B with Schnorr / `bls-min-sig` / `bls-min-pk`.
pub const TWIN_PREFIX_SIZE: usize = TWIN_M_OFFSET + 1;

/// Length of a twin fact block payload naming `m` subgroup members (FR71,
/// DEC-278, little-endian): `proof_header[HEADER_SIZE] ‖ proof_payload_hash[32] ‖
/// snapshot u32 ‖ m u8 ‖ members[m] u32`. The one statement of the layout, shared by
/// the framing and the writer.
pub const fn twin_evidence_size(m: usize) -> usize {
    TWIN_PREFIX_SIZE + 4 * m
}

// The largest round-opening fact block fits every block-size tier's payload.
const _: () = assert!(twin_evidence_size(APPROVAL_MAX_SUBGROUP) <= MAX_PAYLOAD_SIZE);

/// Frames a twin fact block payload: its length, or `None` for an `m` above
/// [`APPROVAL_MAX_SUBGROUP`] or a frame longer than `payload`.
fn twin_frame(payload: &[u8]) -> Option<usize> {
    let m = usize::from(*payload.get(TWIN_M_OFFSET)?);
    if m > APPROVAL_MAX_SUBGROUP {
        return None;
    }
    let len = twin_evidence_size(m);
    (len <= payload.len()).then_some(len)
}

/// Borrowed view of a twin fact block payload (`payload_type == 5`).
///
/// The proof is the *other* twin's full header and its payload hash: the
/// branch's own twin is on the branch. `c`, `s` and `hash(P)` are the proof
/// header's creator, sequence and previous hash. `m = 0` is a penalty-only block;
/// `m ≥ 1` opens an approval round whose ranked subgroup is `members`. Framed like
/// [`BlockView::content_length`]'s arm, padding-tolerant.
pub struct TwinEvidenceView<'a> {
    bytes: &'a [u8],
}

impl<'a> TwinEvidenceView<'a> {
    /// Frames `payload` as a twin fact block; `None` when it does not frame.
    pub fn from_payload(payload: &'a [u8]) -> Option<Self> {
        let len = twin_frame(payload)?;
        Some(Self {
            bytes: &payload[..len],
        })
    }

    /// The other twin's header, signature included.
    pub fn proof_header(&self) -> &'a [u8] {
        &self.bytes[..HEADER_SIZE]
    }

    /// The equivocator `c`: the proof header's creator.
    pub fn creator(&self) -> u32 {
        read_u32_le(self.bytes, CREATOR_OFFSET)
    }

    /// The twin sequence `s`: the proof header's sequence.
    pub fn sequence(&self) -> u32 {
        read_u32_le(self.bytes, SEQUENCE_OFFSET)
    }

    /// The proof header's payload type.
    pub fn proof_payload_type(&self) -> u8 {
        self.bytes[PAYLOAD_TYPE_OFFSET]
    }

    /// `hash(P)`, the twins' shared parent: the proof header's previous hash.
    pub fn parent_hash(&self) -> &'a [u8] {
        &self.bytes[PREVIOUS_HASH_OFFSET..SIGNATURE_OFFSET]
    }

    /// The other twin's creator signature.
    pub fn proof_signature(&self) -> &'a [u8] {
        &self.bytes[SIGNATURE_OFFSET..HEADER_SIZE]
    }

    /// The SHA-256 hash of the other twin's payload.
    pub fn proof_payload_hash(&self) -> &'a [u8] {
        &self.bytes[HEADER_SIZE..TWIN_SNAPSHOT_OFFSET]
    }

    /// The bytes the other twin's signature signs (FR70, DEC-272).
    pub fn proof_signing_preimage(&self) -> [u8; SIGNING_PREIMAGE_SIZE] {
        let mut hash = [0u8; HASH_SIZE];
        hash.copy_from_slice(self.proof_payload_hash());
        signing_preimage_of(self.bytes, &hash)
    }

    /// `c`'s accumulated vote after this block's interest step, before its reset
    /// (FR72): the FR23 inverse.
    pub fn snapshot(&self) -> u32 {
        read_u32_le(self.bytes, TWIN_SNAPSHOT_OFFSET)
    }

    /// The round's subgroup size; 0 for a penalty-only block.
    pub fn m(&self) -> u8 {
        self.bytes[TWIN_M_OFFSET]
    }

    /// Subgroup member `i` in ascending `node_value` order; `None` for `i ≥ m`.
    pub fn member(&self, i: usize) -> Option<u32> {
        (i < usize::from(self.m())).then(|| read_u32_le(self.bytes, TWIN_PREFIX_SIZE + 4 * i))
    }
}

/// Owned immutable canonical block representation.
///
/// `Block` owns the serialized bytes in an internal fixed-size buffer. Use
/// [`view`](Self::view) to obtain a zero-copy [`BlockView`] when only borrowed
/// access is needed (typical for outcome enums and intake APIs).
///
/// `Debug`, `Clone`, and `PartialEq` are intentionally omitted to minimise
/// binary size on embedded targets.
pub struct Block {
    data: [u8; MAX_BLOCK_SIZE],
    len: usize,
}

impl Block {
    /// Creates an owned block from encoded bytes.
    ///
    /// Validates structure via [`BlockView::from_bytes`] then copies the bytes
    /// into the internal buffer.
    ///
    /// Parameters:
    /// - `bytes`: encoded block bytes.
    ///
    /// Example:
    /// ```
    /// use moonblokz_chain_types::Block;
    ///
    /// let mut bytes = [0u8; moonblokz_chain_types::HEADER_SIZE];
    /// bytes[0] = 1;
    /// let block_result = Block::from_bytes(&bytes);
    /// assert!(block_result.is_ok());
    /// let block = match block_result {
    ///     Ok(value) => value,
    ///     Err(_) => return,
    /// };
    /// assert_eq!(block.len(), moonblokz_chain_types::HEADER_SIZE);
    /// ```
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, BlockError> {
        // Structural validation is owned by `BlockView::from_bytes`; reuse it
        // here to keep the rules in one place. The view is discarded after
        // validation — we own the bytes by copying them into our fixed buffer.
        let _validated_view = BlockView::from_bytes(bytes)?;

        let mut data = [0u8; MAX_BLOCK_SIZE];
        data[..bytes.len()].copy_from_slice(bytes);
        Ok(Self {
            data,
            len: bytes.len(),
        })
    }

    /// Returns a zero-copy [`BlockView`] borrowing from this block's bytes.
    ///
    /// Example:
    /// ```
    /// use moonblokz_chain_types::{Block, HEADER_SIZE};
    ///
    /// let mut bytes = [0u8; HEADER_SIZE];
    /// bytes[0] = 1;
    /// let block = match Block::from_bytes(&bytes) {
    ///     Ok(value) => value,
    ///     Err(_) => return,
    /// };
    /// let view = block.view();
    /// assert_eq!(view.version(), 1);
    /// ```
    pub fn view(&self) -> BlockView<'_> {
        // `Block` is only constructable via `from_bytes` or
        // `BlockBuilder::build_signed`, both of which guarantee the bytes
        // satisfy `BlockView`'s invariants —
        // skip re-validation.
        BlockView {
            bytes: &self.data[..self.len],
        }
    }

    /// Returns the canonical serialized bytes for this block.
    ///
    /// Example:
    /// ```
    /// use moonblokz_chain_types::{BlockBuilder, BlockHeader};
    /// use moonblokz_crypto::{Crypto, CryptoTrait, PRIVATE_KEY_SIZE};
    ///
    /// let crypto = Crypto::new([1u8; PRIVATE_KEY_SIZE])
    ///     .ok()
    ///     .expect("test private key should be accepted");
    ///
    /// let header = BlockHeader {
    ///     version: 1,
    ///     sequence: 0,
    ///     creator: 0,
    ///     mined_amount: 0,
    ///     payload_type: 0,
    ///     consumed_votes: 0,
    ///     first_voted_node: 0,
    ///     consumed_votes_from_first_voted_node: 0,
    ///     previous_hash: [0; 32],
    ///     signature: [0; moonblokz_crypto::SIGNATURE_SIZE],
    /// };
    ///
    /// let block = match BlockBuilder::new().header(header).build_signed(&crypto) {
    ///     Ok(value) => value,
    ///     Err(_) => return,
    /// };
    /// assert!(!block.serialized_bytes().is_empty());
    /// ```
    pub fn serialized_bytes(&self) -> &[u8] {
        &self.data[..self.len]
    }

    /// Returns the canonical block hash.
    pub fn hash(&self) -> [u8; HASH_SIZE] {
        self.view().hash()
    }

    /// Returns the encoded length in bytes.
    //
    // A `Block` always has at least `HEADER_SIZE` bytes, so it can never be
    // empty. An `is_empty()` method would be misleading.
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        self.len
    }

    /// Recovers the block's exact serialized byte length structurally — see
    /// [`BlockView::content_length`].
    ///
    /// For a `Block` built from exact wire bytes this equals [`Self::len`]. For
    /// one returned by a storage backend it does not: `len()` is then the padded
    /// slot width, and this is the block.
    pub fn content_length(&self) -> Option<usize> {
        self.view().content_length()
    }

    /// Block version. `0` is reserved for storage empty-slot markers.
    pub fn version(&self) -> u8 {
        self.view().version()
    }

    /// Block sequence number.
    pub fn sequence(&self) -> u32 {
        self.view().sequence()
    }

    /// Creator node id.
    pub fn creator(&self) -> u32 {
        self.view().creator()
    }

    /// Mined amount (excluding transaction fees).
    pub fn mined_amount(&self) -> u32 {
        self.view().mined_amount()
    }

    /// Payload type discriminator.
    pub fn payload_type(&self) -> u8 {
        self.view().payload_type()
    }

    /// Consumed votes.
    pub fn consumed_votes(&self) -> u32 {
        self.view().consumed_votes()
    }

    /// First voted node id.
    pub fn first_voted_node(&self) -> u32 {
        self.view().first_voted_node()
    }

    /// Consumed votes from first voted node.
    pub fn consumed_votes_from_first_voted_node(&self) -> u32 {
        self.view().consumed_votes_from_first_voted_node()
    }

    /// Previous block hash (32 bytes, borrowed).
    pub fn previous_hash(&self) -> &[u8] {
        self.view().previous_hash()
    }

    /// Block signature (`SIGNATURE_SIZE` bytes, borrowed).
    pub fn signature(&self) -> &[u8] {
        self.view().signature()
    }

    /// Returns the payload slice.
    ///
    /// Example:
    /// ```
    /// use moonblokz_chain_types::{Block, HEADER_SIZE};
    ///
    /// let mut bytes = [0u8; HEADER_SIZE + 3];
    /// bytes[0] = 1;
    /// bytes[HEADER_SIZE] = 1;
    /// bytes[HEADER_SIZE + 1] = 2;
    /// bytes[HEADER_SIZE + 2] = 3;
    /// let block = match Block::from_bytes(&bytes) {
    ///     Ok(b) => b,
    ///     Err(_) => return,
    /// };
    /// assert_eq!(block.payload(), &[1, 2, 3]);
    /// ```
    pub fn payload(&self) -> &[u8] {
        self.view().payload()
    }

    /// Returns a transaction block payload view if `payload_type() == 1`.
    pub fn transactions(&self) -> Option<TransactionBlockPayloadView<'_>> {
        self.view().transactions()
    }

    /// Returns a balance block payload view if `payload_type() == 2`.
    pub fn balances(&self) -> Option<BalanceBlockPayloadView<'_>> {
        self.view().balances()
    }
}

/// Builder for immutable `Block` values.
pub struct BlockBuilder {
    header: BlockHeader,
    payload: [u8; MAX_PAYLOAD_SIZE],
    payload_len: usize,
    // `u32` for the balance count (DEC-222); a transaction payload's count stays
    // `u16` and is bounded in `append_item`.
    item_count: u32,
    max_node_id: u32,
}

impl BlockBuilder {
    /// Creates a new builder with zeroed/default header and empty payload.
    ///
    /// Note:
    /// - Default header version is `0`.
    /// - Before building a valid MoonBlokz block, set a non-zero version via
    ///   `header(...)`.
    ///
    /// Parameters:
    /// - none.
    ///
    /// Example:
    /// ```
    /// use moonblokz_chain_types::BlockBuilder;
    ///
    /// let _builder = BlockBuilder::new();
    /// ```
    //
    // `Default` is intentionally not implemented: construction through an
    // explicit `new()` call makes the zero-version starting state visible
    // to callers and avoids accidental default-construction.
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self {
            header: BlockHeader {
                version: 0,
                sequence: 0,
                creator: 0,
                mined_amount: 0,
                payload_type: 0,
                consumed_votes: 0,
                first_voted_node: 0,
                consumed_votes_from_first_voted_node: 0,
                previous_hash: [0; 32],
                signature: [0; SIGNATURE_SIZE],
            },
            payload: [0u8; MAX_PAYLOAD_SIZE],
            payload_len: 0,
            item_count: 0,
            max_node_id: 0,
        }
    }

    /// Sets the full fixed header for the block under construction.
    ///
    /// Parameters:
    /// - `header`: parsed header fields to encode.
    ///
    /// Example:
    /// ```
    /// use moonblokz_chain_types::{BlockBuilder, BlockHeader};
    ///
    /// let header = BlockHeader {
    ///     version: 1,
    ///     sequence: 0,
    ///     creator: 0,
    ///     mined_amount: 0,
    ///     payload_type: 0,
    ///     consumed_votes: 0,
    ///     first_voted_node: 0,
    ///     consumed_votes_from_first_voted_node: 0,
    ///     previous_hash: [0; 32],
    ///     signature: [0; moonblokz_crypto::SIGNATURE_SIZE],
    /// };
    /// let _builder = BlockBuilder::new().header(header);
    /// ```
    pub fn header(mut self, header: BlockHeader) -> Self {
        self.header = header;
        self
    }

    // -- Type-safe add methods --

    /// Adds a node-transfer transaction to the block payload.
    ///
    /// The payload type is automatically set to `PAYLOAD_TYPE_TRANSACTION` on the
    /// first call. Subsequent calls must be consistent (only transaction types).
    pub fn add_node_transfer(&mut self, tx: &NodeTransfer) -> Result<&mut Self, BlockError> {
        self.ensure_managed_payload(PAYLOAD_TYPE_TRANSACTION)?;
        self.append_item(tx.as_bytes())
    }

    /// Adds a registration transaction to the block payload.
    pub fn add_registration(&mut self, tx: &Registration) -> Result<&mut Self, BlockError> {
        self.ensure_managed_payload(PAYLOAD_TYPE_TRANSACTION)?;
        self.append_item(tx.as_bytes())
    }

    /// Adds a complex transaction to the block payload.
    pub fn add_complex_transaction(
        &mut self,
        tx: &ComplexTransaction,
    ) -> Result<&mut Self, BlockError> {
        self.ensure_managed_payload(PAYLOAD_TYPE_TRANSACTION)?;
        self.append_item(tx.as_bytes())
    }

    /// Adds a transaction from its raw binary form to the block payload.
    pub fn add_transaction_bytes(&mut self, bytes: &[u8]) -> Result<&mut Self, BlockError> {
        self.ensure_managed_payload(PAYLOAD_TYPE_TRANSACTION)?;
        self.append_item(bytes)
    }

    /// Sets the chain-config payload from its raw binary form.
    ///
    /// Unlike the transaction/balance builders, a chain-config
    /// (`PAYLOAD_TYPE_CHAIN_CONFIG`) block carries the config bytes *verbatim*
    /// with no leading item-count framing — the single structural fact
    /// (`block == [header | payload]`) that chain-config content-matching relies
    /// on. This sets `payload_type` to `PAYLOAD_TYPE_CHAIN_CONFIG` and must be the
    /// only payload-setting call on the builder; an empty `bytes` slice yields a
    /// header-only chain-config block. Because the payload's hash is signed
    /// by `build_signed` (FR70), this produces a Block #1 whose signature
    /// covers its chain-config content (the genesis FR54 second block).
    pub fn set_chain_config_payload(&mut self, bytes: &[u8]) -> Result<&mut Self, BlockError> {
        if self.payload_len != 0 {
            return Err(BlockError::MalformedBlock("payload type mismatch"));
        }
        if self.header.payload_type != 0 && self.header.payload_type != PAYLOAD_TYPE_CHAIN_CONFIG {
            return Err(BlockError::MalformedBlock("payload type mismatch"));
        }
        if bytes.len() > MAX_PAYLOAD_SIZE {
            return Err(BlockError::PayloadTooLarge {
                max: MAX_PAYLOAD_SIZE,
                actual: bytes.len(),
            });
        }
        self.header.payload_type = PAYLOAD_TYPE_CHAIN_CONFIG;
        self.payload[..bytes.len()].copy_from_slice(bytes);
        self.payload_len = bytes.len();
        Ok(self)
    }

    /// Sets the approval evidence payload's length to `len` and hands out the
    /// builder's own payload buffer to write it in place.
    ///
    /// The evidence is written straight into this buffer (and the aggregate
    /// serialized into it) so that no second payload-sized buffer is needed on
    /// the stack: the copy-in setters' pattern is departed from for that reason
    /// only. Sets `payload_type` to `PAYLOAD_TYPE_APPROVAL`; refused when the
    /// header names another type or `len > MAX_PAYLOAD_SIZE`. It may be called
    /// again to change the length; the buffer's contents are kept.
    pub fn approval_payload_mut(&mut self, len: usize) -> Result<&mut [u8], BlockError> {
        self.raw_payload_mut(len, PAYLOAD_TYPE_APPROVAL)
    }

    /// Sets the twin fact block payload's length to `len` and hands out the
    /// builder's payload buffer to write it in place, as
    /// [`approval_payload_mut`](Self::approval_payload_mut) does for type 4. Sets
    /// `payload_type` to `PAYLOAD_TYPE_TWIN_EVIDENCE`.
    pub fn twin_evidence_payload_mut(&mut self, len: usize) -> Result<&mut [u8], BlockError> {
        self.raw_payload_mut(len, PAYLOAD_TYPE_TWIN_EVIDENCE)
    }

    /// The in-place writers' common body: refused when the header names another
    /// type or `len > MAX_PAYLOAD_SIZE`; the buffer's contents are kept.
    fn raw_payload_mut(&mut self, len: usize, payload_type: u8) -> Result<&mut [u8], BlockError> {
        if self.header.payload_type != 0 && self.header.payload_type != payload_type {
            return Err(BlockError::MalformedBlock("payload type mismatch"));
        }
        if len > MAX_PAYLOAD_SIZE {
            return Err(BlockError::PayloadTooLarge {
                max: MAX_PAYLOAD_SIZE,
                actual: len,
            });
        }
        self.header.payload_type = payload_type;
        self.payload_len = len;
        Ok(&mut self.payload[..len])
    }

    /// Adds a node-info balance entry to the block payload.
    ///
    /// The payload type is automatically set to `PAYLOAD_TYPE_BALANCE` on the
    /// first call. Subsequent calls must be consistent (only balance entries).
    /// The `max_node_id` is tracked automatically from the added entries;
    /// use `set_max_node_id` to override.
    pub fn add_node_info(&mut self, ni: &NodeInfo) -> Result<&mut Self, BlockError> {
        self.ensure_managed_payload(PAYLOAD_TYPE_BALANCE)?;
        let bytes = ni.as_bytes();
        let new_len = self.payload_len + bytes.len();
        if new_len > MAX_PAYLOAD_SIZE {
            return Err(BlockError::PayloadTooLarge {
                max: MAX_PAYLOAD_SIZE,
                actual: new_len,
            });
        }
        let item_count = self
            .item_count
            .checked_add(1)
            .ok_or(BlockError::MalformedBlock("too many balance entries"))?;
        self.payload[self.payload_len..new_len].copy_from_slice(bytes);
        self.payload_len = new_len;
        self.item_count = item_count;
        self.payload[0..4].copy_from_slice(&self.item_count.to_le_bytes());
        let owner = ni.owner();
        if owner > self.max_node_id {
            self.max_node_id = owner;
            self.payload[BALANCE_MAX_NODE_ID_OFFSET..BALANCE_HEADER_SIZE]
                .copy_from_slice(&self.max_node_id.to_le_bytes());
        }
        Ok(self)
    }

    /// Sets the `max_node_id` for a balance block.
    ///
    /// This overrides the auto-tracked value. Only valid for balance payloads.
    pub fn set_max_node_id(&mut self, max_node_id: u32) -> Result<&mut Self, BlockError> {
        self.ensure_managed_payload(PAYLOAD_TYPE_BALANCE)?;
        self.max_node_id = max_node_id;
        self.payload[BALANCE_MAX_NODE_ID_OFFSET..BALANCE_HEADER_SIZE]
            .copy_from_slice(&self.max_node_id.to_le_bytes());
        Ok(self)
    }

    fn ensure_managed_payload(&mut self, expected_type: u8) -> Result<(), BlockError> {
        if self.payload_len == 0 {
            if self.header.payload_type != 0 && self.header.payload_type != expected_type {
                return Err(BlockError::MalformedBlock("payload type mismatch"));
            }
            self.header.payload_type = expected_type;
            match expected_type {
                PAYLOAD_TYPE_TRANSACTION => {
                    self.payload[0..2].copy_from_slice(&0u16.to_le_bytes());
                    self.payload_len = 2;
                }
                PAYLOAD_TYPE_BALANCE => {
                    self.payload[..BALANCE_HEADER_SIZE].fill(0);
                    self.payload_len = BALANCE_HEADER_SIZE;
                }
                _ => {}
            }
        } else if self.header.payload_type != expected_type {
            return Err(BlockError::MalformedBlock("payload type mismatch"));
        }
        Ok(())
    }

    /// Appends one transaction. The payload's transaction count is a `u16`: a
    /// protocol bound of 65 535 transactions per block (DEC-222), which limits the
    /// count, not the block.
    fn append_item(&mut self, bytes: &[u8]) -> Result<&mut Self, BlockError> {
        let new_len = self.payload_len + bytes.len();
        if new_len > MAX_PAYLOAD_SIZE {
            return Err(BlockError::PayloadTooLarge {
                max: MAX_PAYLOAD_SIZE,
                actual: new_len,
            });
        }
        let item_count = u16::try_from(self.item_count + 1)
            .map_err(|_| BlockError::MalformedBlock("too many transactions"))?;
        self.payload[self.payload_len..new_len].copy_from_slice(bytes);
        self.payload_len = new_len;
        self.item_count = u32::from(item_count);
        self.payload[0..2].copy_from_slice(&item_count.to_le_bytes());
        Ok(self)
    }

    /// Builds and signs the immutable block.
    ///
    /// The signing input is the FR70 preimage ([`BlockView::signing_preimage`]):
    /// the header before the signature field followed by `H(payload)`. The
    /// returned owned [`Block`] stores the signer-produced signature in the
    /// header signature field.
    /// `BlockHeader::signature` is intentionally ignored: builders must finish
    /// through this method so callers cannot accidentally construct unsigned
    /// blocks.
    ///
    /// Parameters:
    /// - `crypto`: `moonblokz-crypto` signer handle used to sign canonical bytes.
    ///
    /// Example:
    /// ```
    /// use moonblokz_chain_types::{BlockBuilder, BlockHeader};
    /// use moonblokz_crypto::{Crypto, CryptoTrait, PRIVATE_KEY_SIZE};
    ///
    /// let crypto = Crypto::new([1u8; PRIVATE_KEY_SIZE])
    ///     .ok()
    ///     .expect("test private key should be accepted");
    ///
    /// let header = BlockHeader {
    ///     version: 1,
    ///     sequence: 0,
    ///     creator: 0,
    ///     mined_amount: 0,
    ///     payload_type: 0,
    ///     consumed_votes: 0,
    ///     first_voted_node: 0,
    ///     consumed_votes_from_first_voted_node: 0,
    ///     previous_hash: [0; 32],
    ///     signature: [0; moonblokz_crypto::SIGNATURE_SIZE],
    /// };
    ///
    /// let block_result = BlockBuilder::new().header(header).build_signed(&crypto);
    /// assert!(block_result.is_ok());
    /// let block = match block_result {
    ///     Ok(value) => value,
    ///     Err(_) => return,
    /// };
    /// assert_eq!(block.len(), moonblokz_chain_types::HEADER_SIZE);
    /// assert!(block.signature().iter().any(|value| *value != 0));
    /// ```
    pub fn build_signed<Crypto: CryptoTrait>(self, crypto: &Crypto) -> Result<Block, BlockError> {
        if self.header.version == 0 {
            return Err(BlockError::MalformedBlock("block version must be non-zero"));
        }

        let len = HEADER_SIZE + self.payload_len;
        if len > MAX_BLOCK_SIZE {
            return Err(BlockError::InputTooLarge {
                max: MAX_BLOCK_SIZE,
                actual: len,
            });
        }

        let mut data = [0u8; MAX_BLOCK_SIZE];

        data[VERSION_OFFSET] = self.header.version;
        data[SEQUENCE_OFFSET..SEQUENCE_OFFSET + 4]
            .copy_from_slice(&self.header.sequence.to_le_bytes());
        data[CREATOR_OFFSET..CREATOR_OFFSET + 4]
            .copy_from_slice(&self.header.creator.to_le_bytes());
        data[MINED_AMOUNT_OFFSET..MINED_AMOUNT_OFFSET + 4]
            .copy_from_slice(&self.header.mined_amount.to_le_bytes());
        data[PAYLOAD_TYPE_OFFSET] = self.header.payload_type;
        data[CONSUMED_VOTES_OFFSET..CONSUMED_VOTES_OFFSET + 4]
            .copy_from_slice(&self.header.consumed_votes.to_le_bytes());
        data[FIRST_VOTED_NODE_OFFSET..FIRST_VOTED_NODE_OFFSET + 4]
            .copy_from_slice(&self.header.first_voted_node.to_le_bytes());
        data[CONSUMED_VOTES_FROM_FIRST_OFFSET..CONSUMED_VOTES_FROM_FIRST_OFFSET + 4]
            .copy_from_slice(
                &self
                    .header
                    .consumed_votes_from_first_voted_node
                    .to_le_bytes(),
            );
        data[PREVIOUS_HASH_OFFSET..PREVIOUS_HASH_OFFSET + 32]
            .copy_from_slice(&self.header.previous_hash);

        if self.payload_len > 0 {
            data[PAYLOAD_OFFSET..PAYLOAD_OFFSET + self.payload_len]
                .copy_from_slice(&self.payload[..self.payload_len]);
        }

        // FR70: the signature field is not part of what is signed. With
        // `H(payload)` written where the signature goes, the preimage is
        // `data[..SIGNING_PREIMAGE_SIZE]`: no second buffer stays live
        // across the signing call (stack budget), and the signature then
        // overwrites the hash.
        let payload_hash = calculate_hash(&data[PAYLOAD_OFFSET..len]);
        data[SIGNATURE_OFFSET..SIGNING_PREIMAGE_SIZE].copy_from_slice(&payload_hash);
        let signature = crypto.sign(&data[..SIGNING_PREIMAGE_SIZE]);
        data[SIGNATURE_OFFSET..HEADER_SIZE].copy_from_slice(signature.serialize());

        Ok(Block { data, len })
    }
}

impl AsRef<[u8]> for Block {
    fn as_ref(&self) -> &[u8] {
        self.serialized_bytes()
    }
}

pub(crate) fn read_u32_le(data: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ])
}

pub(crate) fn read_u64_le(data: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
        data[offset + 4],
        data[offset + 5],
        data[offset + 6],
        data[offset + 7],
    ])
}

#[cfg(test)]
mod tests {
    use super::*;
    use moonblokz_crypto::{Crypto, CryptoTrait, PRIVATE_KEY_SIZE};
    use moonblokz_crypto::{PUBLIC_KEY_SIZE, SIGNATURE_SIZE};

    fn test_crypto() -> Crypto {
        // `CryptoError` has no `Debug` even under test, so `.expect()` cannot be
        // called on the `Result` directly — unlike `BlockError`, which does
        // derive it (`error.rs`). Hence `.ok()` first.
        Crypto::new([1u8; PRIVATE_KEY_SIZE])
            .ok()
            .expect("test private key should be accepted")
    }

    fn any_nonzero(bytes: &[u8]) -> bool {
        bytes.iter().any(|value| *value != 0)
    }

    fn sample_header() -> BlockHeader {
        BlockHeader {
            version: 2,
            sequence: 42,
            creator: 7,
            mined_amount: 11,
            payload_type: 3,
            consumed_votes: 101,
            first_voted_node: 19,
            consumed_votes_from_first_voted_node: 17,
            previous_hash: [9u8; 32],
            signature: [5u8; SIGNATURE_SIZE],
        }
    }

    // ===================================================================
    // `content_length` — exact-length recovery from a padded read-back
    // (FR59). Every test below parses the block from a **padded** buffer,
    // because that is the only shape the problem actually occurs in.
    // ===================================================================

    /// Simulates a durable read-back: the exact bytes, zero-padded out to the
    /// fixed slot width, exactly as `MemoryBackend::read_block` returns them.
    fn padded_slot(block: &Block) -> [u8; MAX_BLOCK_SIZE] {
        let mut slot = [0u8; MAX_BLOCK_SIZE];
        let exact = block.serialized_bytes();
        slot[..exact.len()].copy_from_slice(exact);
        slot
    }

    /// Asserts the round trip that FR59 depends on: after padding, the slice
    /// length is the slot width and only `content_length()` still knows the
    /// block — and trimming to it reproduces the original bytes *and hash*.
    fn assert_recovers(block: &Block) {
        let exact = block.serialized_bytes();
        let slot = padded_slot(block);
        let read_back = Block::from_bytes(&slot).expect("padded slot parses");

        assert_eq!(
            read_back.len(),
            MAX_BLOCK_SIZE,
            "precondition: read-back is padded"
        );
        let recovered = read_back
            .content_length()
            .expect("content_length recovers a well-framed block");
        assert_eq!(
            recovered,
            exact.len(),
            "recovered length must equal the wire length"
        );

        let view = BlockView::from_bytes(&slot[..recovered]).expect("trimmed view parses");
        assert_eq!(
            view.serialized_bytes(),
            exact,
            "trimmed bytes must be the original bytes"
        );
        assert_eq!(
            view.hash(),
            block.view().hash(),
            "trimmed hash must be the real hash"
        );
        assert_ne!(
            read_back.hash(),
            block.view().hash(),
            "the padded hash must differ - that is the bug this prevents"
        );
    }

    /// Copies a freshly signed chain-config payload into a fixed buffer — the
    /// crate is `no_std`, so tests carry arrays, not `Vec`s. Mirrors
    /// `chain_config::tests::signed_payload_bytes`.
    fn signed_config_payload(
        builder: &mut crate::chain_config::ChainConfigPayloadBuilder,
    ) -> ([u8; MAX_PAYLOAD_SIZE], usize) {
        let mut bytes = [0u8; MAX_PAYLOAD_SIZE];
        let signed = builder.build_signed(&test_crypto());
        bytes[..signed.len()].copy_from_slice(signed);
        (bytes, signed.len())
    }

    fn transaction_block_with_signature(tx_signature: &[u8; SIGNATURE_SIZE]) -> Block {
        let nt = NodeTransfer::new(99, 10, 1, 2, 1000, 5, 42, tx_signature);
        let mut builder = BlockBuilder::new().header(BlockHeader {
            payload_type: 0,
            ..sample_header()
        });
        builder.add_node_transfer(&nt).unwrap();
        builder.build_signed(&test_crypto()).unwrap()
    }

    #[test]
    fn content_length_recovers_a_transaction_block() {
        assert_recovers(&transaction_block_with_signature(&[0xAA; SIGNATURE_SIZE]));
    }

    #[test]
    fn content_length_recovers_a_balance_block() {
        let ni = NodeInfo::new(3, 5000, 12, &[7u8; PUBLIC_KEY_SIZE]);
        let mut builder = BlockBuilder::new().header(BlockHeader {
            payload_type: 0,
            ..sample_header()
        });
        builder.add_node_info(&ni).unwrap();
        builder.set_max_node_id(9).unwrap();
        assert_recovers(&builder.build_signed(&test_crypto()).unwrap());
    }

    /// DEC-222: the balance count is a `u32`. No shipped tier holds more than
    /// 65 535 entries, so the width is proven on hand-built bytes.
    #[test]
    fn balance_count_is_read_as_a_u32() {
        let mut bytes = [0u8; HEADER_SIZE + BALANCE_HEADER_SIZE];
        bytes[VERSION_OFFSET] = 1;
        bytes[PAYLOAD_TYPE_OFFSET] = PAYLOAD_TYPE_BALANCE;
        bytes[PAYLOAD_OFFSET..PAYLOAD_OFFSET + 4].copy_from_slice(&65_537u32.to_le_bytes());
        bytes[PAYLOAD_OFFSET + 4..PAYLOAD_OFFSET + 8].copy_from_slice(&7u32.to_le_bytes());
        let view = BlockView::from_bytes(&bytes).unwrap();
        let balances = view.balances().unwrap();
        assert_eq!(balances.count(), 65_537);
        assert_eq!(balances.max_node_id(), 7);
        // The declared count over-runs the bytes: no structural length.
        assert_eq!(view.content_length(), None);
    }

    /// The 8-byte balance prefix leaves room for 39 / 16 / 28 entries per reference block
    /// (Schnorr / min-sig / min-pk, DEC-251); one more is refused.
    #[cfg(feature = "block-size-2016")]
    #[test]
    fn a_reference_balance_block_holds_the_entries_its_payload_fits() {
        let fit = (MAX_PAYLOAD_SIZE - 8) / crate::NODE_INFO_SIZE;
        #[cfg(feature = "schnorr")]
        assert_eq!(fit, 39);
        #[cfg(feature = "bls-min-sig")]
        assert_eq!(fit, 16);
        #[cfg(feature = "bls-min-pk")]
        assert_eq!(fit, 28);
        let mut builder = BlockBuilder::new().header(BlockHeader {
            payload_type: 0,
            ..sample_header()
        });
        for owner in 0..fit as u32 {
            builder
                .add_node_info(&NodeInfo::new(owner, 1, 0, &[1u8; PUBLIC_KEY_SIZE]))
                .unwrap();
        }
        let one_more =
            builder.add_node_info(&NodeInfo::new(fit as u32, 1, 0, &[1u8; PUBLIC_KEY_SIZE]));
        assert!(matches!(one_more, Err(BlockError::PayloadTooLarge { .. })));
    }

    /// DEC-222: a transaction payload's count stays a `u16`, a protocol bound of
    /// 65 535 transactions per block. No tier fits that many, so the bound is
    /// driven through the builder's counter.
    #[test]
    fn the_65536th_transaction_is_refused() {
        let mut builder = BlockBuilder::new().header(BlockHeader {
            payload_type: 0,
            ..sample_header()
        });
        builder
            .add_transaction_bytes(&[3, 0, 0, 0, 0, 0, 0])
            .unwrap();
        builder.item_count = u32::from(u16::MAX);
        let (len_before, count_before) = (
            builder.payload_len,
            [builder.payload[0], builder.payload[1]],
        );
        let result = builder.add_transaction_bytes(&[3, 0, 0, 0, 0, 0, 0]);
        assert!(matches!(
            result,
            Err(BlockError::MalformedBlock("too many transactions"))
        ));
        // Refused before anything is written.
        assert_eq!(builder.payload_len, len_before);
        assert_eq!([builder.payload[0], builder.payload[1]], count_before);
        assert_eq!(builder.item_count, u32::from(u16::MAX));
    }

    #[test]
    fn content_length_recovers_a_chain_config_block() {
        let mut payload_builder = crate::chain_config::ChainConfigPayloadBuilder::new();
        payload_builder.add_literal(21, &[100, 0]).unwrap();
        payload_builder.add_literal(7, &[1, 2, 3]).unwrap();
        let (payload_bytes, payload_len) = signed_config_payload(&mut payload_builder);
        let payload = &payload_bytes[..payload_len];

        let mut builder = BlockBuilder::new().header(BlockHeader {
            payload_type: PAYLOAD_TYPE_CHAIN_CONFIG,
            ..sample_header()
        });
        builder.set_chain_config_payload(payload).unwrap();
        assert_recovers(&builder.build_signed(&test_crypto()).unwrap());
    }

    #[test]
    fn content_length_recovers_a_complex_transaction_with_mixed_item_types() {
        let sig = [0x5A; SIGNATURE_SIZE];
        let mut cx = ComplexTransaction::new(4);
        cx.add_utxo_input(1, 2, 400, &sig).unwrap();
        cx.add_balance_input(7, 3, 900, 0, &sig).unwrap();
        cx.add_utxo_output(&[2u8; PUBLIC_KEY_SIZE], 400).unwrap();
        cx.add_balance_output(5, 500).unwrap();

        let mut builder = BlockBuilder::new().header(BlockHeader {
            payload_type: 0,
            ..sample_header()
        });
        builder.add_complex_transaction(&cx).unwrap();
        let block = builder.build_signed(&test_crypto()).unwrap();

        // 5 (tx header) + 2 (counts) + UTXO input (15 + SIG) + balance input (25 + SIG) +
        // UTXO output (9 + PK) + balance output 13 = 69 + 2 SIG + PK (229 under Schnorr),
        // + the 2-byte payload transaction count, + the block header.
        let tx_len = 69 + 2 * SIGNATURE_SIZE + PUBLIC_KEY_SIZE;
        assert_eq!(block.len(), HEADER_SIZE + 2 + tx_len);
        assert_recovers(&block);
    }

    /// The case that rules out a trailing-zero scan: the block's own last
    /// content byte is `0x00`, so "walk back over the zeros" would truncate a
    /// legitimate block and compute a wrong hash.
    #[test]
    fn content_length_is_not_fooled_by_content_ending_in_zero() {
        let mut tx_signature = [0xAA; SIGNATURE_SIZE];
        tx_signature[SIGNATURE_SIZE - 1] = 0;
        let block = transaction_block_with_signature(&tx_signature);
        assert_eq!(*block.serialized_bytes().last().unwrap(), 0);
        assert_recovers(&block);
    }

    /// Same hazard on the chain-config walk: the final entry's value ends in a
    /// zero byte, inside the signed content region.
    #[test]
    fn content_length_is_not_fooled_by_a_chain_config_value_ending_in_zero() {
        let mut payload_builder = crate::chain_config::ChainConfigPayloadBuilder::new();
        payload_builder.add_literal(21, &[5, 0, 0]).unwrap();
        let (payload_bytes, payload_len) = signed_config_payload(&mut payload_builder);
        let payload = &payload_bytes[..payload_len];

        let mut builder = BlockBuilder::new().header(BlockHeader {
            payload_type: PAYLOAD_TYPE_CHAIN_CONFIG,
            ..sample_header()
        });
        builder.set_chain_config_payload(payload).unwrap();
        assert_recovers(&builder.build_signed(&test_crypto()).unwrap());
    }

    /// A zero-item payload is `HEADER_SIZE + count field` — and a padded slot
    /// decodes its zero padding as exactly that, so the two are structurally
    /// indistinguishable. Tier 1 rejects header-only type-1/2 blocks (their
    /// payload views require the count field), so no such block can reach
    /// durable storage and the ambiguity is unreachable in practice.
    #[test]
    fn content_length_of_empty_transaction_and_balance_payloads() {
        let empty_tx = BlockBuilder::new()
            .header(BlockHeader {
                payload_type: PAYLOAD_TYPE_TRANSACTION,
                ..sample_header()
            })
            .build_signed(&test_crypto())
            .unwrap();
        let slot = padded_slot(&empty_tx);
        let read_back = Block::from_bytes(&slot).expect("parses");
        assert_eq!(read_back.content_length(), Some(HEADER_SIZE + 2));

        let empty_balance = BlockBuilder::new()
            .header(BlockHeader {
                payload_type: PAYLOAD_TYPE_BALANCE,
                ..sample_header()
            })
            .build_signed(&test_crypto())
            .unwrap();
        let slot = padded_slot(&empty_balance);
        let read_back = Block::from_bytes(&slot).expect("parses");
        assert_eq!(
            read_back.content_length(),
            Some(HEADER_SIZE + BALANCE_HEADER_SIZE)
        );
    }

    #[test]
    fn content_length_refuses_a_count_that_over_runs_the_buffer() {
        // A transaction payload declaring 600 transactions it does not carry:
        // the walk runs out of buffer and refuses rather than guessing.
        let mut bytes = [0u8; MAX_BLOCK_SIZE];
        bytes[VERSION_OFFSET] = 1;
        bytes[PAYLOAD_TYPE_OFFSET] = PAYLOAD_TYPE_TRANSACTION;
        bytes[PAYLOAD_OFFSET] = 0x58; // 600 little-endian
        bytes[PAYLOAD_OFFSET + 1] = 0x02;
        bytes[PAYLOAD_OFFSET + 2] = 1; // a node-transfer discriminant, then nothing
        let view = BlockView::from_bytes(&bytes).expect("parses");
        assert_eq!(view.content_length(), None);
    }

    /// AC1 names an unknown transaction/input/output discriminant as a refusal
    /// case in its own right: the payload frames correctly as far as the count,
    /// and only the item's type byte is unrecognised.
    #[test]
    fn content_length_refuses_an_unknown_transaction_discriminant() {
        let mut bytes = [0u8; MAX_BLOCK_SIZE];
        bytes[VERSION_OFFSET] = 1;
        bytes[PAYLOAD_TYPE_OFFSET] = PAYLOAD_TYPE_TRANSACTION;
        bytes[PAYLOAD_OFFSET] = 1; // one transaction declared, and it is present
        bytes[PAYLOAD_OFFSET + 2] = 9; // ...but 9 is not a transaction type
        let view = BlockView::from_bytes(&bytes).expect("parses");
        assert_eq!(view.content_length(), None);
    }

    /// The same for a complex transaction's input discriminant, which is walked
    /// by a different arm.
    #[test]
    fn content_length_refuses_an_unknown_complex_input_discriminant() {
        let mut bytes = [0u8; MAX_BLOCK_SIZE];
        bytes[VERSION_OFFSET] = 1;
        bytes[PAYLOAD_TYPE_OFFSET] = PAYLOAD_TYPE_TRANSACTION;
        bytes[PAYLOAD_OFFSET] = 1; // one transaction
        bytes[PAYLOAD_OFFSET + 2] = 3; // complex
        bytes[PAYLOAD_OFFSET + 2 + 5] = 1; // one input
        bytes[PAYLOAD_OFFSET + 2 + 6] = 0; // zero outputs
        bytes[PAYLOAD_OFFSET + 2 + 7] = 7; // ...and 7 is not an input type
        let view = BlockView::from_bytes(&bytes).expect("parses");
        assert_eq!(view.content_length(), None);
    }

    #[test]
    fn content_length_refuses_an_unknown_payload_type() {
        let mut bytes = [0u8; MAX_BLOCK_SIZE];
        bytes[VERSION_OFFSET] = 1;
        bytes[PAYLOAD_TYPE_OFFSET] = 9;
        let view = BlockView::from_bytes(&bytes).expect("parses");
        assert_eq!(view.content_length(), None);
    }

    // ===================================================================
    // Approval evidence framing (DEC-195, Story 6.6 AC2)
    // ===================================================================

    const APPROVAL_DEVIATION: u32 = 77;

    /// Writes an evidence payload for a subgroup of `m` whose ranks `held` signed
    /// (a real aggregate, signers in rank order) with `late` late entries, and
    /// returns its framed length.
    fn write_approval(out: &mut [u8], m: u8, held: &[usize], late: u16) -> usize {
        use moonblokz_crypto::{AggregatedSignatureTrait, MultiSignature, PublicKeyTrait};
        let message = b"approval-test";
        let mut sigs: [Option<MultiSignature>; MAX_AGGREGATED_SIGNATURES] =
            core::array::from_fn(|_| None);
        let mut keys = [[0u8; PUBLIC_KEY_SIZE]; MAX_AGGREGATED_SIGNATURES];
        for (i, rank) in held.iter().enumerate() {
            let signer = Crypto::new([*rank as u8 + 1; PRIVATE_KEY_SIZE])
                .ok()
                .expect("test key");
            sigs[i] = Some(signer.multi_sign(message));
            keys[i] = *signer.public_key().serialize();
        }
        let sig_refs: [&MultiSignature; MAX_AGGREGATED_SIGNATURES] =
            core::array::from_fn(|i| sigs[i.min(held.len() - 1)].as_ref().expect("signed"));
        let key_refs: [&[u8; PUBLIC_KEY_SIZE]; MAX_AGGREGATED_SIGNATURES] =
            core::array::from_fn(|i| &keys[i]);
        let aggregate = test_crypto()
            .aggregate_signatures(&sig_refs[..held.len()], &key_refs[..held.len()], message)
            .ok()
            .expect("aggregates");

        out[..8].copy_from_slice(&0x0102_0304_0506_0708u64.to_le_bytes());
        out[8..12].copy_from_slice(&APPROVAL_DEVIATION.to_le_bytes());
        out[12] = m;
        let bitmap = APPROVAL_PREFIX_SIZE..APPROVAL_PREFIX_SIZE + usize::from(m).div_ceil(8);
        out[bitmap.clone()].fill(0);
        for rank in held {
            out[APPROVAL_PREFIX_SIZE + rank / 8] |= 1 << (rank % 8);
        }
        let written = aggregate
            .serialize(&mut out[bitmap.end..])
            .ok()
            .expect("serializes");
        let fixed = approval_fixed_size(usize::from(m), held.len());
        assert_eq!(
            bitmap.end + written + 2,
            fixed,
            "layout agrees with the writer"
        );
        out[fixed - 2..fixed].copy_from_slice(&late.to_le_bytes());
        for i in 0..usize::from(late) {
            let at = fixed + APPROVAL_LATE_ENTRY_SIZE * i;
            out[at..at + 4].copy_from_slice(&(i as u32 + 100).to_le_bytes());
            out[at + 4..at + 8].copy_from_slice(&(i as u32 * 10).to_le_bytes());
        }
        fixed + APPROVAL_LATE_ENTRY_SIZE * usize::from(late)
    }

    fn approval_block(m: u8, held: &[usize], late: u16) -> Block {
        let mut builder = BlockBuilder::new().header(BlockHeader {
            payload_type: 0,
            ..sample_header()
        });
        let buffer = builder
            .approval_payload_mut(MAX_PAYLOAD_SIZE)
            .expect("type 0");
        let len = write_approval(buffer, m, held, late);
        builder.approval_payload_mut(len).expect("shrinks");
        builder.build_signed(&test_crypto()).expect("signs")
    }

    /// Story 6.6 AC2: the evidence frames from its own fields, and a bit flip
    /// in the padding after it no longer loses the block (deferred-work D52).
    #[test]
    fn content_length_frames_an_approval_and_ignores_its_padding() {
        let block = approval_block(5, &[0, 2, 4], 2);
        assert_eq!(block.view().payload_type(), PAYLOAD_TYPE_APPROVAL);
        assert_recovers(&block);

        let exact = block.len();
        let mut slot = padded_slot(&block);
        slot[exact] = 0xFF;
        slot[MAX_BLOCK_SIZE - 1] = 0x01;
        let view = BlockView::from_bytes(&slot).expect("parses");
        assert_eq!(view.content_length(), Some(exact));
    }

    /// The pin that used to answer an all-zero approval flips: a type-4 block
    /// always carries its content, so the empty payload no longer frames; and
    /// every malformed shape of AC2 refuses rather than guesses.
    #[test]
    fn content_length_refuses_an_empty_or_malformed_approval() {
        let mut bytes = [0u8; MAX_BLOCK_SIZE];
        bytes[VERSION_OFFSET] = 1;
        bytes[PAYLOAD_TYPE_OFFSET] = PAYLOAD_TYPE_APPROVAL;
        let empty = BlockView::from_bytes(&bytes[..HEADER_SIZE]).expect("parses");
        assert_eq!(empty.content_length(), None, "the empty payload");
        let zeros = BlockView::from_bytes(&bytes).expect("parses");
        assert_eq!(zeros.content_length(), None, "an all-zero payload: n == 0");

        let block = approval_block(5, &[0, 2, 4], 2);
        let exact = block.len();
        let base = padded_slot(&block);
        let frames = |mutate: &dyn Fn(&mut [u8; MAX_BLOCK_SIZE]), len: usize| {
            let mut slot = base;
            mutate(&mut slot);
            BlockView::from_bytes(&slot[..len])
                .expect("parses")
                .content_length()
        };
        let p = HEADER_SIZE;
        assert_eq!(frames(&|_| {}, exact), Some(exact), "the passing fixture");
        assert_eq!(
            frames(&|_| {}, exact - 1),
            None,
            "frame longer than the slice"
        );
        assert_eq!(
            frames(
                &|s| s[p + 12] = (2 * MAX_AGGREGATED_SIGNATURES) as u8,
                MAX_BLOCK_SIZE
            ),
            None,
            "m above 2·MAX_AGGREGATED_SIGNATURES − 1"
        );
        assert_eq!(
            frames(&|s| s[p + APPROVAL_PREFIX_SIZE] = 0, MAX_BLOCK_SIZE),
            None,
            "n == 0"
        );
        assert_eq!(
            frames(
                &|s| {
                    s[p + 12] = (2 * MAX_AGGREGATED_SIGNATURES - 1) as u8;
                    let bitmap = (2 * MAX_AGGREGATED_SIGNATURES - 1).div_ceil(8);
                    s[p + APPROVAL_PREFIX_SIZE..p + APPROVAL_PREFIX_SIZE + bitmap].fill(0xFF);
                },
                MAX_BLOCK_SIZE
            ),
            None,
            "n above MAX_AGGREGATED_SIGNATURES"
        );
        let fixed = approval_fixed_size(5, 3);
        assert_eq!(
            frames(
                &|s| s[p + fixed - 2..p + fixed].copy_from_slice(&u16::MAX.to_le_bytes()),
                MAX_BLOCK_SIZE
            ),
            None,
            "late_count overflows the frame"
        );
        #[cfg(feature = "schnorr")]
        assert_eq!(
            frames(&|s| s[p + APPROVAL_PREFIX_SIZE] |= 1 << 1, MAX_BLOCK_SIZE),
            None,
            "a Schnorr aggregate whose count is not the bitmap's population"
        );
    }

    /// Story 6.7 AC2: every field of a real evidence block reads back as written,
    /// a rank-8 signer on the bitmap's second byte included (LSB-first).
    #[test]
    fn approval_view_reads_every_field() {
        let held = [0usize, 3, 8];
        let block = approval_block(9, &held, 3);
        let view = ApprovalView::from_payload(block.view().payload()).expect("frames");
        assert_eq!(view.supporter_vote_sum(), 0x0102_0304_0506_0708);
        assert_eq!(view.deviation_sequence(), APPROVAL_DEVIATION);
        assert_eq!(view.m(), 9);
        assert_eq!(view.bitmap(), &[0b0000_1001, 0b0000_0001]);
        assert_eq!(view.signer_count(), held.len() as u32);
        let fixed = approval_fixed_size(9, held.len());
        assert_eq!(
            view.aggregate().len(),
            fixed - APPROVAL_PREFIX_SIZE - 2 - APPROVAL_LATE_COUNT_SIZE
        );
        use moonblokz_crypto::{AggregatedSignature, AggregatedSignatureTrait};
        let aggregate = AggregatedSignature::new(view.aggregate())
            .ok()
            .expect("the aggregate parses");
        assert_eq!(aggregate.get_count(), held.len());
        assert_eq!(view.late_count(), 3);
        for i in 0..3 {
            assert_eq!(view.late_entry(i), Some((i as u32 + 100, i as u32 * 10)));
        }
        assert_eq!(view.late_entry(3), None);
        // Padding after the frame is not read.
        let mut padded = [0u8; MAX_PAYLOAD_SIZE];
        let payload = block.view().payload();
        padded[..payload.len()].copy_from_slice(payload);
        padded[payload.len()..].fill(0xAA);
        let view = ApprovalView::from_payload(&padded).expect("frames with padding");
        assert_eq!(view.late_count(), 3);
        assert_eq!(view.late_entry(3), None);
    }

    #[test]
    fn approval_view_reads_the_deviation_and_frames_like_content_length() {
        let block = approval_block(9, &[1, 8], 0);
        let view = ApprovalView::from_payload(block.view().payload()).expect("frames");
        assert_eq!(view.deviation_sequence(), APPROVAL_DEVIATION);
        assert!(ApprovalView::from_payload(&[0u8; 64]).is_none());
    }

    /// The fixed part is computed from the crypto constants; at
    /// `required_support = 40` (`m = 79`) it is the KB's figure per scheme.
    #[test]
    fn approval_fixed_size_matches_the_ratified_layout_figures() {
        let fixed = approval_fixed_size(79, 40);
        #[cfg(feature = "schnorr")]
        assert_eq!(fixed, 1339);
        #[cfg(feature = "bls-min-sig")]
        assert_eq!(fixed, 75);
        #[cfg(feature = "bls-min-pk")]
        assert_eq!(fixed, 123);
        assert_eq!(
            fixed,
            13 + 10
                + AGGREGATED_SIGNATURE_CONSTANT_SIZE
                + AGGREGATED_SIGNATURE_VARIABLE_SIZE * 40
                + 2
        );
        // The late-entry room in a 2 016 B block (configuration ID 3's
        // default), as the builder computes it.
        let room = (2016 - HEADER_SIZE - fixed) / APPROVAL_LATE_ENTRY_SIZE;
        #[cfg(feature = "schnorr")]
        assert_eq!(room, 69);
        #[cfg(feature = "bls-min-sig")]
        assert_eq!(room, 229);
        #[cfg(feature = "bls-min-pk")]
        assert_eq!(room, 217);
    }

    #[test]
    fn approval_payload_mut_sets_the_type_and_refuses_a_mismatch() {
        let mut builder = BlockBuilder::new().header(sample_header());
        assert!(
            builder.approval_payload_mut(4).is_err(),
            "header names type 3"
        );

        let mut builder = BlockBuilder::new().header(BlockHeader {
            payload_type: 0,
            ..sample_header()
        });
        assert!(builder.approval_payload_mut(MAX_PAYLOAD_SIZE + 1).is_err());
        builder.approval_payload_mut(4).expect("type 0")[3] = 0xAB;
        assert_eq!(builder.approval_payload_mut(8).expect("again")[3], 0xAB);
        assert!(
            builder.add_transaction_bytes(&[0u8; 4]).is_err(),
            "no transaction after it"
        );
        let block = builder.build_signed(&test_crypto()).expect("signs");
        assert_eq!(block.view().payload_type(), PAYLOAD_TYPE_APPROVAL);
        assert_eq!(block.len(), HEADER_SIZE + 8);
    }

    /// For a block parsed from its exact wire bytes the two lengths agree; the
    /// whole point is that they stop agreeing once storage pads it.
    #[test]
    fn content_length_equals_len_for_exact_wire_bytes() {
        let block = transaction_block_with_signature(&[0xAA; SIGNATURE_SIZE]);
        let parsed = Block::from_bytes(block.serialized_bytes()).expect("parses");
        assert_eq!(parsed.content_length(), Some(parsed.len()));
    }

    #[test]
    fn builder_round_trip_from_bytes() {
        let sig = [0xAA; SIGNATURE_SIZE];
        let nt = NodeTransfer::new(99, 10, 1, 2, 1000, 5, 42, &sig);
        let mut builder = BlockBuilder::new().header(BlockHeader {
            payload_type: 0,
            ..sample_header()
        });
        builder.add_node_transfer(&nt).unwrap();
        let block = builder.build_signed(&test_crypto()).unwrap();

        let parsed = Block::from_bytes(block.serialized_bytes()).unwrap();

        assert_eq!(parsed.version(), 2);
        assert_eq!(parsed.sequence(), 42);
        assert_eq!(parsed.creator(), 7);
        assert_eq!(parsed.mined_amount(), 11);
        assert_eq!(parsed.payload_type(), PAYLOAD_TYPE_TRANSACTION);
        assert_eq!(parsed.consumed_votes(), 101);
        assert_eq!(parsed.first_voted_node(), 19);
        assert_eq!(parsed.consumed_votes_from_first_voted_node(), 17);
        assert_eq!(parsed.previous_hash(), &[9u8; 32][..]);
        assert!(any_nonzero(parsed.signature()));
        let tx = parsed.transactions().unwrap().iter().next().unwrap();
        assert_eq!(tx.as_node_transfer().unwrap().amount(), 1000);
    }

    #[test]
    fn from_bytes_rejects_oversize() {
        let bytes = [0u8; MAX_BLOCK_SIZE + 1];
        let result = Block::from_bytes(&bytes);
        assert!(matches!(result, Err(BlockError::InputTooLarge { .. })));
    }

    #[test]
    fn from_bytes_rejects_too_small() {
        let bytes = [0u8; HEADER_SIZE - 1];
        let result = Block::from_bytes(&bytes);
        assert!(matches!(result, Err(BlockError::InputTooSmall { .. })));
    }

    #[test]
    fn from_bytes_rejects_zero_version() {
        let bytes = [0u8; HEADER_SIZE];
        let result = Block::from_bytes(&bytes);
        assert!(matches!(
            result,
            Err(BlockError::MalformedBlock("block version must be non-zero"))
        ));
    }

    #[test]
    fn build_rejects_zero_version() {
        let result = BlockBuilder::new().build_signed(&test_crypto());
        assert!(matches!(
            result,
            Err(BlockError::MalformedBlock("block version must be non-zero"))
        ));
    }

    #[test]
    fn accessors_return_expected_values() {
        let mut prev = [0u8; 32];
        prev[0] = 99;
        let mut sig = [0u8; SIGNATURE_SIZE];
        sig[SIGNATURE_SIZE - 1] = 88;

        let header = BlockHeader {
            previous_hash: prev,
            signature: sig,
            ..sample_header()
        };

        let block = BlockBuilder::new()
            .header(header)
            .build_signed(&test_crypto())
            .unwrap();

        assert_eq!(block.version(), 2);
        assert_eq!(block.sequence(), 42);
        assert_eq!(block.creator(), 7);
        assert_eq!(block.mined_amount(), 11);
        assert_eq!(block.payload_type(), 3);
        assert_eq!(block.consumed_votes(), 101);
        assert_eq!(block.first_voted_node(), 19);
        assert_eq!(block.consumed_votes_from_first_voted_node(), 17);
        assert_eq!(block.previous_hash()[0], 99);
        assert!(any_nonzero(block.signature()));
        assert!(block.payload().is_empty());
    }

    #[test]
    fn max_block_size_accepted() {
        let mut bytes = [0u8; MAX_BLOCK_SIZE];
        bytes[0] = 1;
        let block = Block::from_bytes(&bytes).unwrap();
        assert_eq!(block.len(), MAX_BLOCK_SIZE);
        assert_eq!(block.payload().len(), MAX_PAYLOAD_SIZE);
    }

    #[test]
    fn header_only_block_has_empty_payload() {
        let block = BlockBuilder::new()
            .header(sample_header())
            .build_signed(&test_crypto())
            .unwrap();
        assert!(block.payload().is_empty());
        assert_eq!(block.len(), HEADER_SIZE);
    }

    #[test]
    fn set_chain_config_payload_round_trips_verbatim() {
        let header = BlockHeader {
            version: 1,
            sequence: 1,
            creator: 0,
            mined_amount: 0,
            payload_type: 0,
            consumed_votes: 0,
            first_voted_node: 0,
            consumed_votes_from_first_voted_node: 0,
            previous_hash: [0x42; 32],
            signature: [0u8; SIGNATURE_SIZE],
        };
        let config_bytes = [0xC0, 0xA5, 0xF6, 0x01, 0x02, 0x03];
        let mut builder = BlockBuilder::new().header(header);
        builder.set_chain_config_payload(&config_bytes).unwrap();
        let block = builder.build_signed(&test_crypto()).unwrap();

        assert_eq!(block.payload_type(), PAYLOAD_TYPE_CHAIN_CONFIG);
        // Chain-config payload is the raw bytes verbatim — no item framing.
        assert_eq!(block.payload(), &config_bytes[..]);
        assert_eq!(block.previous_hash(), &[0x42; 32][..]);
        assert!(any_nonzero(block.signature()), "block must be signed");
        assert_eq!(block.len(), HEADER_SIZE + config_bytes.len());
    }

    #[test]
    fn set_chain_config_payload_empty_yields_header_only() {
        let mut builder = BlockBuilder::new().header(sample_header());
        builder.set_chain_config_payload(&[]).unwrap();
        let block = builder.build_signed(&test_crypto()).unwrap();

        assert_eq!(block.payload_type(), PAYLOAD_TYPE_CHAIN_CONFIG);
        assert!(block.payload().is_empty());
        assert_eq!(block.len(), HEADER_SIZE);
    }

    #[test]
    fn set_chain_config_payload_rejects_oversized() {
        let oversized = [0u8; MAX_PAYLOAD_SIZE + 1];
        let mut builder = BlockBuilder::new().header(sample_header());
        assert!(matches!(
            builder.set_chain_config_payload(&oversized),
            Err(BlockError::PayloadTooLarge { .. })
        ));
    }

    #[test]
    fn set_chain_config_payload_rejects_type_mismatch() {
        // A builder that already holds transaction items rejects a later
        // chain-config payload call.
        let signer = test_crypto();
        let tx = crate::NodeTransfer::new_signed(0, 0, 0, 0, 1, 0, 0, &signer);
        let mut builder = BlockBuilder::new();
        builder.add_node_transfer(&tx).unwrap();
        assert!(matches!(
            builder.set_chain_config_payload(&[0x01]),
            Err(BlockError::MalformedBlock(_))
        ));
    }

    #[test]
    fn block_hash_methods_use_canonical_bytes() {
        let block = BlockBuilder::new()
            .header(sample_header())
            .build_signed(&test_crypto())
            .unwrap();
        let view = block.view();

        assert_eq!(block.hash(), calculate_hash(block.serialized_bytes()));
        assert_eq!(view.hash(), block.hash());
    }

    #[test]
    fn serialized_bytes_matches_expected_layout() {
        let header = BlockHeader {
            version: 1,
            sequence: 0x04030201,
            creator: 0x08070605,
            mined_amount: 0x0C0B0A09,
            payload_type: 0x0D,
            consumed_votes: 0x11100F0E,
            first_voted_node: 0x15141312,
            consumed_votes_from_first_voted_node: 0x19181716,
            previous_hash: [0xAA; 32],
            signature: [0xBB; SIGNATURE_SIZE],
        };

        let block = BlockBuilder::new()
            .header(header)
            .build_signed(&test_crypto())
            .unwrap();
        let bytes = block.serialized_bytes();

        assert_eq!(bytes[0], 1); // version
        assert_eq!(&bytes[1..5], &[0x01, 0x02, 0x03, 0x04]); // sequence LE
        assert_eq!(&bytes[5..9], &[0x05, 0x06, 0x07, 0x08]); // creator LE
        assert_eq!(&bytes[9..13], &[0x09, 0x0A, 0x0B, 0x0C]); // mined_amount LE
        assert_eq!(bytes[13], 0x0D); // payload_type
        assert_eq!(&bytes[14..18], &[0x0E, 0x0F, 0x10, 0x11]); // consumed_votes LE
        assert_eq!(&bytes[18..22], &[0x12, 0x13, 0x14, 0x15]); // first_voted_node LE
        assert_eq!(&bytes[22..26], &[0x16, 0x17, 0x18, 0x19]); // consumed_votes_from_first LE
        assert_eq!(&bytes[26..58], &[0xAA; 32]); // previous_hash
        assert!(any_nonzero(&bytes[58..HEADER_SIZE])); // signature supplied by crypto
        assert_eq!(bytes.len(), HEADER_SIZE);
    }

    // -- Add method tests --

    #[test]
    fn block_builder_add_node_transfer() {
        let sig = [0xAA; SIGNATURE_SIZE];
        let nt = NodeTransfer::new(99, 10, 1, 2, 1000, 5, 42, &sig);
        let mut builder = BlockBuilder::new().header(BlockHeader {
            payload_type: 0,
            ..sample_header()
        });
        builder.add_node_transfer(&nt).unwrap();
        let block = builder.build_signed(&test_crypto()).unwrap();
        assert_eq!(block.payload_type(), PAYLOAD_TYPE_TRANSACTION);
        let txp = block.transactions().unwrap();
        assert_eq!(txp.count(), 1);
        let tx = txp.iter().next().unwrap();
        assert_eq!(tx.vote(), 99);
        let nv = tx.as_node_transfer().unwrap();
        assert_eq!(nv.amount(), 1000);
    }

    #[test]
    fn block_builder_add_two_node_transfers() {
        let sig = [0xAA; SIGNATURE_SIZE];
        let nt1 = NodeTransfer::new(1, 10, 1, 2, 100, 1, 0, &sig);
        let nt2 = NodeTransfer::new(2, 20, 3, 4, 200, 2, 1, &sig);
        let mut builder = BlockBuilder::new().header(BlockHeader {
            payload_type: 0,
            ..sample_header()
        });
        builder.add_node_transfer(&nt1).unwrap();
        builder.add_node_transfer(&nt2).unwrap();
        let block = builder.build_signed(&test_crypto()).unwrap();
        let txp = block.transactions().unwrap();
        assert_eq!(txp.count(), 2);
        let mut iter = txp.iter();
        assert_eq!(
            iter.next().unwrap().as_node_transfer().unwrap().amount(),
            100
        );
        assert_eq!(
            iter.next().unwrap().as_node_transfer().unwrap().amount(),
            200
        );
        assert!(iter.next().is_none());
    }

    #[test]
    fn block_builder_add_transaction_bytes() {
        let sig = [0xAA; SIGNATURE_SIZE];
        let nt = NodeTransfer::new(99, 10, 1, 2, 1000, 5, 42, &sig);
        let mut builder = BlockBuilder::new().header(BlockHeader {
            payload_type: 0,
            ..sample_header()
        });
        builder.add_transaction_bytes(nt.as_bytes()).unwrap();
        let block = builder.build_signed(&test_crypto()).unwrap();
        assert_eq!(block.payload_type(), PAYLOAD_TYPE_TRANSACTION);
        let txp = block.transactions().unwrap();
        assert_eq!(txp.count(), 1);
        let tx = txp.iter().next().unwrap();
        assert_eq!(tx.as_node_transfer().unwrap().amount(), 1000);
    }

    #[test]
    fn block_builder_add_node_info() {
        let pub_key = [0xBB; PUBLIC_KEY_SIZE];
        let ni = NodeInfo::new(5, 2000, 3, &pub_key);
        let mut builder = BlockBuilder::new().header(BlockHeader {
            payload_type: 0,
            ..sample_header()
        });
        builder.add_node_info(&ni).unwrap();
        let block = builder.build_signed(&test_crypto()).unwrap();
        assert_eq!(block.payload_type(), PAYLOAD_TYPE_BALANCE);
        let bp = block.balances().unwrap();
        assert_eq!(bp.count(), 1);
        assert_eq!(bp.max_node_id(), 5);
        let entry = bp.iter().next().unwrap();
        assert_eq!(entry.owner(), 5);
        assert_eq!(entry.balance(), 2000);
    }

    #[test]
    fn block_builder_set_max_node_id() {
        let pub_key = [0; PUBLIC_KEY_SIZE];
        let ni = NodeInfo::new(3, 100, 0, &pub_key);
        let mut builder = BlockBuilder::new().header(BlockHeader {
            payload_type: 0,
            ..sample_header()
        });
        builder.add_node_info(&ni).unwrap();
        builder.set_max_node_id(999).unwrap();
        let block = builder.build_signed(&test_crypto()).unwrap();
        let bp = block.balances().unwrap();
        assert_eq!(bp.max_node_id(), 999);
    }

    #[test]
    fn block_builder_rejects_type_mismatch() {
        let sig = [0xAA; SIGNATURE_SIZE];
        let nt = NodeTransfer::new(0, 0, 0, 0, 0, 0, 0, &sig);
        let pub_key = [0; PUBLIC_KEY_SIZE];
        let ni = NodeInfo::new(0, 0, 0, &pub_key);
        let mut builder = BlockBuilder::new().header(BlockHeader {
            payload_type: 0,
            ..sample_header()
        });
        builder.add_node_transfer(&nt).unwrap();
        let result = builder.add_node_info(&ni);
        assert!(matches!(
            result,
            Err(BlockError::MalformedBlock("payload type mismatch"))
        ));
    }

    #[test]
    fn from_bytes_with_truncated_payload() {
        let mut bytes = [0u8; HEADER_SIZE];
        bytes[0] = 1;
        bytes[PAYLOAD_TYPE_OFFSET] = PAYLOAD_TYPE_BALANCE;
        let block = Block::from_bytes(&bytes).unwrap();
        assert!(block.payload().is_empty());
        assert!(block.balances().is_none());
    }

    #[test]
    fn set_max_node_id_lower_than_auto_tracked() {
        let pub_key = [0; PUBLIC_KEY_SIZE];
        let ni = NodeInfo::new(100, 500, 0, &pub_key);
        let mut builder = BlockBuilder::new().header(BlockHeader {
            payload_type: 0,
            ..sample_header()
        });
        builder.add_node_info(&ni).unwrap();
        builder.set_max_node_id(50).unwrap();
        let block = builder.build_signed(&test_crypto()).unwrap();
        let bp = block.balances().unwrap();
        assert_eq!(bp.max_node_id(), 50);
    }

    #[test]
    fn add_methods_reject_at_max_payload() {
        let sig = [0xAA; SIGNATURE_SIZE];
        let nt = NodeTransfer::new(0, 0, 0, 0, 0, 0, 0, &sig);
        let mut builder = BlockBuilder::new().header(BlockHeader {
            payload_type: 0,
            ..sample_header()
        });
        // NODE_TRANSFER_SIZE = 101 after the 2-byte count; on the reference tier
        // 18 * 101 = 1818 <= 1892 and 19 * 101 = 1919 > 1892.
        let fit = (MAX_PAYLOAD_SIZE - 2) / crate::transaction::NODE_TRANSFER_SIZE;
        for _ in 0..fit {
            builder.add_node_transfer(&nt).unwrap();
        }
        let result = builder.add_node_transfer(&nt);
        assert!(matches!(result, Err(BlockError::PayloadTooLarge { .. })));
    }

    // -- BlockView tests (Story 1.1) --

    #[test]
    fn block_view_size_is_pointer_plus_length() {
        // FR65 / AC5: BlockView holds only a slice reference — its working set
        // is `&[u8]` (~16 B on 64-bit targets, ~8 B on 32-bit targets), never
        // the full ~2 KB block buffer.
        let view_size = core::mem::size_of::<BlockView<'_>>();
        let slice_size = core::mem::size_of::<&[u8]>();
        assert_eq!(view_size, slice_size);
    }

    #[test]
    fn block_view_from_bytes_zero_copy_round_trip() {
        // AC2 + AC5: Constructing a BlockView from a serialized block borrows
        // the input bytes without copying; all accessors read back identical
        // field values to the originating builder header.
        let header = BlockHeader {
            previous_hash: [0x11; 32],
            signature: [0x22; SIGNATURE_SIZE],
            ..sample_header()
        };
        let block = BlockBuilder::new()
            .header(header)
            .build_signed(&test_crypto())
            .unwrap();
        let serialized = block.serialized_bytes();

        let view = BlockView::from_bytes(serialized).unwrap();

        // The view's borrowed slice points at the same bytes (same pointer +
        // same length) — proves no copy was made.
        assert!(core::ptr::eq(
            view.serialized_bytes().as_ptr(),
            serialized.as_ptr()
        ));
        assert_eq!(view.serialized_bytes().len(), serialized.len());

        assert_eq!(view.version(), 2);
        assert_eq!(view.sequence(), 42);
        assert_eq!(view.creator(), 7);
        assert_eq!(view.mined_amount(), 11);
        assert_eq!(view.payload_type(), 3);
        assert_eq!(view.consumed_votes(), 101);
        assert_eq!(view.first_voted_node(), 19);
        assert_eq!(view.consumed_votes_from_first_voted_node(), 17);
        assert_eq!(view.previous_hash(), &[0x11; 32][..]);
        assert!(any_nonzero(view.signature()));
    }

    #[test]
    fn block_view_rejects_invalid_inputs() {
        // BlockView::from_bytes shares the structural validation rules with
        // Block::from_bytes — exercise each rejection path.
        let too_small = [0u8; HEADER_SIZE - 1];
        assert!(matches!(
            BlockView::from_bytes(&too_small),
            Err(BlockError::InputTooSmall { .. })
        ));

        let too_large = [0u8; MAX_BLOCK_SIZE + 1];
        assert!(matches!(
            BlockView::from_bytes(&too_large),
            Err(BlockError::InputTooLarge { .. })
        ));

        let zero_version = [0u8; HEADER_SIZE];
        assert!(matches!(
            BlockView::from_bytes(&zero_version),
            Err(BlockError::MalformedBlock("block version must be non-zero"))
        ));
    }

    #[test]
    fn block_view_borrows_from_owned_block() {
        // AC2 + AC4: An owned Block exposes a zero-copy view via `view()`; the
        // view's accessors return identical values to the owned block's
        // accessors, and the borrowed bytes point inside the owned buffer.
        let sig = [0xAA; SIGNATURE_SIZE];
        let nt = NodeTransfer::new(99, 10, 1, 2, 1000, 5, 42, &sig);
        let mut builder = BlockBuilder::new().header(BlockHeader {
            payload_type: 0,
            ..sample_header()
        });
        builder.add_node_transfer(&nt).unwrap();
        let block = builder.build_signed(&test_crypto()).unwrap();

        let view = block.view();

        assert_eq!(view.version(), block.version());
        assert_eq!(view.sequence(), block.sequence());
        assert_eq!(view.creator(), block.creator());
        assert_eq!(view.mined_amount(), block.mined_amount());
        assert_eq!(view.payload_type(), block.payload_type());
        assert_eq!(view.consumed_votes(), block.consumed_votes());
        assert_eq!(view.first_voted_node(), block.first_voted_node());
        assert_eq!(
            view.consumed_votes_from_first_voted_node(),
            block.consumed_votes_from_first_voted_node()
        );
        assert_eq!(view.previous_hash(), block.previous_hash());
        assert_eq!(view.signature(), block.signature());
        assert_eq!(view.payload(), block.payload());
        assert_eq!(view.len(), block.len());

        // Transaction iterator equivalence
        let view_tx = view.transactions().unwrap().iter().next().unwrap();
        let block_tx = block.transactions().unwrap().iter().next().unwrap();
        assert_eq!(view_tx.as_node_transfer().unwrap().amount(), 1000);
        assert_eq!(block_tx.as_node_transfer().unwrap().amount(), 1000);
    }

    #[test]
    fn block_view_max_size_parse_no_alloc() {
        // AC5: A serialized block of the maximum configured size is parsed by
        // BlockView::from_bytes without allocation (this crate is no_std with
        // no allocator linked) and the working set is bounded by the input
        // slice, not by a fresh buffer.
        let mut bytes = [0u8; MAX_BLOCK_SIZE];
        bytes[0] = 1;
        let view = BlockView::from_bytes(&bytes).unwrap();
        assert_eq!(view.len(), MAX_BLOCK_SIZE);
        assert_eq!(view.payload().len(), MAX_PAYLOAD_SIZE);
        assert!(core::ptr::eq(
            view.serialized_bytes().as_ptr(),
            bytes.as_ptr()
        ));
    }

    #[test]
    fn block_view_transactions_returns_none_for_non_transaction_payload_type() {
        // payload_type != PAYLOAD_TYPE_TRANSACTION must yield None.
        let block = BlockBuilder::new()
            .header(BlockHeader {
                payload_type: PAYLOAD_TYPE_BALANCE,
                ..sample_header()
            })
            .build_signed(&test_crypto())
            .unwrap();
        let view = BlockView::from_bytes(block.serialized_bytes()).unwrap();
        assert!(view.transactions().is_none());
    }

    #[test]
    fn block_view_balances_returns_none_for_non_balance_payload_type() {
        // payload_type != PAYLOAD_TYPE_BALANCE must yield None.
        let block = BlockBuilder::new()
            .header(BlockHeader {
                payload_type: PAYLOAD_TYPE_TRANSACTION,
                ..sample_header()
            })
            .build_signed(&test_crypto())
            .unwrap();
        let view = BlockView::from_bytes(block.serialized_bytes()).unwrap();
        assert!(view.balances().is_none());
    }

    // ===================================================================
    // FR70 creator-signature preimage (Story 6.12, DEC-272)
    // ===================================================================

    fn preimage_block() -> Block {
        let mut builder = BlockBuilder::new().header(BlockHeader {
            version: 1,
            sequence: 0x04030201,
            creator: 0x08070605,
            mined_amount: 0x0C0B0A09,
            payload_type: 0,
            consumed_votes: 0x11100F0E,
            first_voted_node: 0x15141312,
            consumed_votes_from_first_voted_node: 0x19181716,
            previous_hash: [0xAA; 32],
            signature: [0xBB; SIGNATURE_SIZE],
        });
        builder.set_chain_config_payload(&[1, 2, 3]).unwrap();
        builder.build_signed(&test_crypto()).unwrap()
    }

    fn signature_verifies(bytes: &[u8]) -> bool {
        let view = BlockView::from_bytes(bytes).unwrap();
        let crypto = test_crypto();
        let signature = moonblokz_crypto::Signature::new(view.signature())
            .ok()
            .expect("a block carries a well-formed signature");
        crypto.verify_signature(&view.signing_preimage(), &signature, crypto.public_key())
    }

    /// The golden: the 58 header bytes before the signature, then SHA-256 of the
    /// payload, pinned byte by byte — 90 bytes under every scheme.
    #[test]
    fn signing_preimage_is_the_header_before_the_signature_then_the_payload_hash() {
        let block = preimage_block();
        let mut expected = [0u8; 90];
        expected[..26].copy_from_slice(&[
            1, // version
            0x01,
            0x02,
            0x03,
            0x04, // sequence LE
            0x05,
            0x06,
            0x07,
            0x08, // creator LE
            0x09,
            0x0A,
            0x0B,
            0x0C, // mined_amount LE
            PAYLOAD_TYPE_CHAIN_CONFIG,
            0x0E,
            0x0F,
            0x10,
            0x11, // consumed_votes LE
            0x12,
            0x13,
            0x14,
            0x15, // first_voted_node LE
            0x16,
            0x17,
            0x18,
            0x19, // consumed_votes_from_first_voted_node LE
        ]);
        expected[26..58].copy_from_slice(&[0xAA; 32]);
        // SHA-256(01 02 03).
        expected[58..].copy_from_slice(&[
            0x03, 0x90, 0x58, 0xc6, 0xf2, 0xc0, 0xcb, 0x49, 0x2c, 0x53, 0x3b, 0x0a, 0x4d, 0x14,
            0xef, 0x77, 0xcc, 0x0f, 0x78, 0xab, 0xcc, 0xce, 0xd5, 0x28, 0x7d, 0x84, 0xa1, 0xa2,
            0x01, 0x1c, 0xfb, 0x81,
        ]);
        assert_eq!(SIGNING_PREIMAGE_SIZE, 90);
        assert_eq!(block.view().signing_preimage(), expected);
    }

    #[test]
    fn build_signed_signs_the_preimage() {
        let block = preimage_block();
        assert!(signature_verifies(block.serialized_bytes()));
        // Not the whole block with the signature zero-filled (the pre-FR70 form).
        let mut zeroed = [0u8; MAX_BLOCK_SIZE];
        let bytes = block.serialized_bytes();
        zeroed[..bytes.len()].copy_from_slice(bytes);
        zeroed[SIGNATURE_OFFSET..HEADER_SIZE].fill(0);
        let crypto = test_crypto();
        let signature = moonblokz_crypto::Signature::new(block.signature())
            .ok()
            .expect("well-formed");
        assert!(!crypto.verify_signature(&zeroed[..bytes.len()], &signature, crypto.public_key()));
    }

    #[test]
    fn a_payload_or_header_byte_flip_breaks_the_signature() {
        let block = preimage_block();
        let len = block.len();
        for at in [HEADER_SIZE + 1, CREATOR_OFFSET, PREVIOUS_HASH_OFFSET + 31] {
            let mut bytes = [0u8; MAX_BLOCK_SIZE];
            bytes[..len].copy_from_slice(block.serialized_bytes());
            bytes[at] ^= 0x01;
            assert!(!signature_verifies(&bytes[..len]), "flip at {at}");
        }
    }

    #[test]
    fn the_signature_field_changes_the_hash_not_the_preimage() {
        let block = preimage_block();
        let len = block.len();
        let mut bytes = [0u8; MAX_BLOCK_SIZE];
        bytes[..len].copy_from_slice(block.serialized_bytes());
        bytes[SIGNATURE_OFFSET] ^= 0x01;
        let flipped = BlockView::from_bytes(&bytes[..len]).unwrap();
        assert_ne!(flipped.hash(), block.hash());
        assert_eq!(flipped.signing_preimage(), block.view().signing_preimage());
    }

    // ===================================================================
    // Twin fact block, payload type 5 (Story 6.13, DEC-278)
    // ===================================================================

    /// Writes a twin fact block payload proving `twin` into `out`; returns its
    /// length.
    fn write_twin(out: &mut [u8], twin: &BlockView<'_>, snapshot: u32, members: &[u32]) -> usize {
        out[..HEADER_SIZE].copy_from_slice(&twin.serialized_bytes()[..HEADER_SIZE]);
        out[HEADER_SIZE..TWIN_SNAPSHOT_OFFSET].copy_from_slice(&calculate_hash(twin.payload()));
        out[TWIN_SNAPSHOT_OFFSET..TWIN_M_OFFSET].copy_from_slice(&snapshot.to_le_bytes());
        out[TWIN_M_OFFSET] = u8::try_from(members.len()).unwrap();
        for (i, member) in members.iter().enumerate() {
            let at = TWIN_PREFIX_SIZE + 4 * i;
            out[at..at + 4].copy_from_slice(&member.to_le_bytes());
        }
        twin_evidence_size(members.len())
    }

    fn twin_block(members: &[u32]) -> Block {
        let twin = preimage_block();
        let mut builder = BlockBuilder::new().header(BlockHeader {
            payload_type: 0,
            ..sample_header()
        });
        let out = builder
            .twin_evidence_payload_mut(twin_evidence_size(members.len()))
            .unwrap();
        write_twin(out, &twin.view(), 0x0D0C_0B0A, members);
        builder.build_signed(&test_crypto()).unwrap()
    }

    /// A raw type-5 payload of `len` bytes, for framing refusals.
    fn raw_twin_block(payload: &[u8]) -> Block {
        let mut builder = BlockBuilder::new().header(BlockHeader {
            payload_type: 0,
            ..sample_header()
        });
        builder
            .twin_evidence_payload_mut(payload.len())
            .unwrap()
            .copy_from_slice(payload);
        builder.build_signed(&test_crypto()).unwrap()
    }

    #[test]
    fn twin_view_reads_every_field_of_a_round_opening_block() {
        let twin = preimage_block();
        let block = twin_block(&[3, 1, 4]);
        let view = block.view();
        assert_eq!(view.payload_type(), PAYLOAD_TYPE_TWIN_EVIDENCE);
        let proof = TwinEvidenceView::from_payload(view.payload()).expect("frames");
        assert_eq!(
            proof.proof_header(),
            &twin.serialized_bytes()[..HEADER_SIZE]
        );
        assert_eq!(proof.creator(), 0x0807_0605);
        assert_eq!(proof.sequence(), 0x0403_0201);
        assert_eq!(proof.proof_payload_type(), PAYLOAD_TYPE_CHAIN_CONFIG);
        assert_eq!(proof.parent_hash(), &[0xAA; 32]);
        assert_eq!(proof.proof_signature(), twin.view().signature());
        assert_eq!(proof.proof_payload_hash(), &calculate_hash(twin.payload()));
        assert_eq!(proof.snapshot(), 0x0D0C_0B0A);
        assert_eq!(proof.m(), 3);
        assert_eq!(
            [
                proof.member(0),
                proof.member(1),
                proof.member(2),
                proof.member(3)
            ],
            [Some(3), Some(1), Some(4), None]
        );
        assert_eq!(view.content_length(), Some(block.len()));
        assert_eq!(block.len(), HEADER_SIZE + twin_evidence_size(3));
        assert_recovers(&block);
    }

    #[test]
    fn a_penalty_only_block_frames_without_members() {
        let block = twin_block(&[]);
        let proof = TwinEvidenceView::from_payload(block.payload()).expect("frames");
        assert_eq!(proof.m(), 0);
        assert_eq!(proof.member(0), None);
        assert_eq!(block.content_length(), Some(HEADER_SIZE + TWIN_PREFIX_SIZE));
        assert_recovers(&block);
    }

    /// The layout golden: the proof header, its payload hash, the snapshot, `m`,
    /// then the members, all little-endian, at fixed offsets.
    #[test]
    fn twin_payload_layout_is_pinned() {
        let twin = preimage_block();
        let block = twin_block(&[0x0102_0304, 0x0506_0708]);
        let payload = block.payload();
        assert_eq!(
            &payload[..HEADER_SIZE],
            &twin.serialized_bytes()[..HEADER_SIZE]
        );
        assert_eq!(
            &payload[HEADER_SIZE..HEADER_SIZE + 32],
            &calculate_hash(twin.payload())
        );
        assert_eq!(
            &payload[HEADER_SIZE + 32..],
            &[
                0x0A, 0x0B, 0x0C, 0x0D, // snapshot LE
                2,    // m
                0x04, 0x03, 0x02, 0x01, // member 0 LE
                0x08, 0x07, 0x06, 0x05, // member 1 LE
            ]
        );
    }

    #[test]
    fn twin_sizes_match_the_ratified_figures() {
        #[cfg(feature = "schnorr")]
        let expected = (159, 475, 555);
        #[cfg(feature = "bls-min-sig")]
        let expected = (143, 459, 539);
        #[cfg(feature = "bls-min-pk")]
        let expected = (191, 507, 587);
        assert_eq!(
            (
                TWIN_PREFIX_SIZE,
                twin_evidence_size(79),
                twin_evidence_size(99)
            ),
            expected
        );
    }

    #[test]
    fn content_length_refuses_a_malformed_twin_payload() {
        let full = twin_block(&[7, 8]);
        let payload = full.payload();
        // Cut before `m`.
        assert!(
            raw_twin_block(&payload[..TWIN_PREFIX_SIZE - 1])
                .content_length()
                .is_none()
        );
        // `m = 2` with one member.
        assert!(
            raw_twin_block(&payload[..TWIN_PREFIX_SIZE + 4])
                .content_length()
                .is_none()
        );
        // `m` above the largest subgroup.
        let mut over = [0u8; TWIN_PREFIX_SIZE + 4 * (APPROVAL_MAX_SUBGROUP + 1)];
        over[..TWIN_PREFIX_SIZE].copy_from_slice(&payload[..TWIN_PREFIX_SIZE]);
        over[TWIN_M_OFFSET] = u8::try_from(APPROVAL_MAX_SUBGROUP + 1).unwrap();
        assert!(raw_twin_block(&over).content_length().is_none());
        assert!(TwinEvidenceView::from_payload(&over).is_none());
        // Bytes after the framed length are padding: the frame stays shorter.
        let mut trailing = [0u8; TWIN_PREFIX_SIZE + 4 * 2 + 3];
        trailing[..payload.len()].copy_from_slice(payload);
        let block = raw_twin_block(&trailing);
        assert_eq!(block.content_length(), Some(full.len()));
        assert!(block.content_length() < Some(block.len()));
    }

    /// The proof's preimage is the other twin's own, so its signature verifies
    /// from the header and the payload hash alone (FR70).
    #[test]
    fn the_proof_preimage_is_the_twins_own_and_verifies() {
        let twin = preimage_block();
        let block = twin_block(&[]);
        let proof = TwinEvidenceView::from_payload(block.payload()).unwrap();
        assert_eq!(
            proof.proof_signing_preimage(),
            twin.view().signing_preimage()
        );
        let crypto = test_crypto();
        let signature = moonblokz_crypto::Signature::new(proof.proof_signature())
            .ok()
            .expect("well-formed");
        assert!(crypto.verify_signature(
            &proof.proof_signing_preimage(),
            &signature,
            crypto.public_key()
        ));
    }

    #[test]
    fn twin_evidence_payload_mut_sets_the_type_and_refuses_a_mismatch() {
        let mut builder = BlockBuilder::new().header(sample_header());
        assert!(
            builder.twin_evidence_payload_mut(4).is_err(),
            "header names type 3"
        );
        let mut builder = BlockBuilder::new().header(BlockHeader {
            payload_type: PAYLOAD_TYPE_APPROVAL,
            ..sample_header()
        });
        assert!(
            builder.twin_evidence_payload_mut(4).is_err(),
            "header names type 4"
        );
        let mut builder = BlockBuilder::new().header(BlockHeader {
            payload_type: 0,
            ..sample_header()
        });
        assert!(
            builder
                .twin_evidence_payload_mut(MAX_PAYLOAD_SIZE + 1)
                .is_err()
        );
        assert!(builder.twin_evidence_payload_mut(4).is_ok());
        assert!(
            builder.approval_payload_mut(4).is_err(),
            "no approval after it"
        );
        let block = builder.build_signed(&test_crypto()).expect("signs");
        assert_eq!(block.view().payload_type(), PAYLOAD_TYPE_TWIN_EVIDENCE);
    }
}
