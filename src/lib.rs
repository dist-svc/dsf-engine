#![cfg_attr(not(feature = "std"), no_std)]
#![feature(trait_alias)]

#[cfg(feature = "alloc")]
extern crate alloc;

pub mod comms;

pub mod store;

pub mod engine;

pub mod error;

#[cfg(feature = "defmt")]
mod log {
    pub use defmt::{trace, debug, info, warn, error};

    pub trait Debug = core::fmt::Debug + defmt::Format;
}

#[cfg(not(feature = "defmt"))]
mod log {
    pub use log::{trace, debug, info, warn, error};

    pub trait Debug = core::fmt::Debug;
}
