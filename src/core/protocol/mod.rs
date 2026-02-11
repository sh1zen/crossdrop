#![allow(dead_code)]
//! Secure transfer protocol: integrates security, pipeline, and transaction.
//!
//! This module coordinates all secure transfer operations including:
//! - Secure manifest generation with cryptographic signatures and Merkle roots
//! - Protocol message envelope with authentication and replay protection
//! - Resume protocol with signed requests and bitmap-based chunk tracking
//! - Abuse controls (retry limits, timeout enforcement, manifest authorization)

pub mod manifest;
pub mod coordinator;

