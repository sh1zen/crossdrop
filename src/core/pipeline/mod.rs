#![allow(dead_code)]
//! Transfer pipeline: chunking, Merkle trees, sender/receiver async pipelines.
//!
//! This module implements the high-performance, multi-stage file transfer
//! pipeline with integrity verification, compression, and encryption.

pub mod chunk;
pub mod merkle;
pub mod receiver;
pub mod sender;

