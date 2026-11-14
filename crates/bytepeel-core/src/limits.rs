//! The per-peel item limit: protobuf fields, CBOR/MessagePack values and DER
//! elements all draw from one budget ([`crate::Options::max_items`]).
//!
//! Each item costs a few hundred bytes of memory and tens of bytes of JSON,
//! while it can take as little as one input byte (`00 00 00 …` is a CBOR
//! array's worth of zeros), so without a limit a few megabytes of input build
//! gigabytes. The counter is thread-local so the parsers need no extra
//! argument; [`Scope`] sets it for one peel.

use crate::Diag;
use std::cell::Cell;

thread_local! {
    /// Items the current peel may still build; `usize::MAX` outside a peel.
    static LEFT: Cell<usize> = const { Cell::new(usize::MAX) };
    /// The current peel's limit, for messages.
    static LIMIT: Cell<usize> = const { Cell::new(usize::MAX) };
    /// Set when a parse ran out of items (cleared by [`take_hit`]).
    static HIT: Cell<bool> = const { Cell::new(false) };
}

/// Gives the current thread a fresh item budget until dropped, then restores
/// the previous one (so a peel nested in another is safe).
pub(crate) struct Scope {
    prev: (usize, usize, bool),
}

impl Scope {
    pub(crate) fn new(limit: usize) -> Self {
        Scope {
            prev: (
                LEFT.replace(limit),
                LIMIT.replace(limit),
                HIT.replace(false),
            ),
        }
    }
}

impl Drop for Scope {
    fn drop(&mut self) {
        LEFT.set(self.prev.0);
        LIMIT.set(self.prev.1);
        HIT.set(self.prev.2);
    }
}

/// Account for one item starting at `at`.
pub(crate) fn charge(at: usize) -> Result<(), Diag> {
    let left = LEFT.get();
    if left == 0 {
        HIT.set(true);
        return Err(too_many(Some(at)));
    }
    LEFT.set(left - 1);
    Ok(())
}

/// Items left; with [`restore`], lets a caller refund a losing candidate.
pub(crate) fn left() -> usize {
    LEFT.get()
}

pub(crate) fn restore(left: usize) {
    LEFT.set(left);
}

/// Whether a parse ran out of items since the last call (and clear it).
pub(crate) fn take_hit() -> bool {
    HIT.replace(false)
}

pub(crate) fn too_many(at: Option<usize>) -> Diag {
    Diag::new(
        "TOO_MANY_ITEMS",
        format!(
            "more than {} protobuf fields, CBOR/MessagePack values and DER elements \
             (raise --max-items to decode it)",
            LIMIT.get()
        ),
        at,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn budget_counts_down_and_scopes_restore() {
        assert_eq!(left(), usize::MAX);
        {
            let _s = Scope::new(2);
            assert!(charge(0).is_ok() && charge(1).is_ok());
            let e = charge(2).unwrap_err();
            assert_eq!((e.code, e.offset), ("TOO_MANY_ITEMS", Some(2)));
            assert!(e.message.contains("more than 2 "), "{}", e.message);
            assert!(take_hit() && !take_hit());
            {
                let _inner = Scope::new(5);
                assert_eq!(left(), 5);
            }
            assert_eq!(left(), 0);
        }
        assert_eq!(left(), usize::MAX);
    }
}
