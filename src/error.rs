/*! Error types for MoonBlokz canonical chain types. */

/// Errors returned by block parsing and block construction.
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
