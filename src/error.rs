/*! Error types for MoonBlokz canonical chain types.

# Design note — embedded target

This is an embedded (`no_std`) library optimised for minimal binary size.
`Debug`, `Display`, and similar trait implementations are intentionally
omitted to avoid pulling formatting machinery into the final binary.
*/

/// Errors returned by block parsing and block construction.
///
/// Trait implementations such as `Debug` and `Display` are intentionally
/// omitted to minimise binary size on embedded targets.
#[cfg_attr(test, derive(Debug))]
pub enum BlockError {
    /// Input buffer is shorter than the required minimum block size.
    InputTooSmall { min: usize, actual: usize },
    /// Input buffer exceeds the maximum block size.
    InputTooLarge { max: usize, actual: usize },
    /// Payload exceeds payload capacity for a block.
    PayloadTooLarge { max: usize, actual: usize },
    /// Block bytes are structurally invalid.
    MalformedBlock(&'static str),
}
