#![no_std]
#![feature(generic_associated_types)]
#![feature(trait_alias)]

#[cfg(feature = "alloc")]
extern crate alloc;

pub mod comms;

pub mod store;

