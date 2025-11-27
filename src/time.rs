//! # Time support module.
#![deny(missing_docs)]
use core::fmt::Debug;

/// Generic abstraction for a check/countdown timer. Should also be cheap to copy and clone.
pub trait Countdown: Debug {
    /// The countdown has expired.
    fn has_expired(&self) -> bool;
    /// Reset the countdown to its initial state.
    fn reset(&mut self);
}
