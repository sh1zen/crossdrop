//! Connection ticket for peer addressing.
//!
//! Tickets are compressed, serialized endpoint addresses that can be
//! shared with peers to establish connections.

use crate::utils::hash;
use anyhow::Context;
use iroh::EndpointAddr;
use serde::{Deserialize, Serialize};
use tracing::error;

/// A connection ticket containing an endpoint address.
#[derive(Debug, Serialize, Deserialize)]
pub struct Ticket {
    pub address: EndpointAddr,
}

impl Ticket {
    /// Create a new ticket from an endpoint address.
    pub fn new(endpoint: EndpointAddr) -> Self {
        Self { address: endpoint }
    }

    /// Export a ticket to a compressed string.
    pub fn export(this: Ticket) -> anyhow::Result<String> {
        hash::compress_string(serde_json::to_string(&this)?).map_err(|e| {
            error!(
                event = "ticket_encode_failure",
                error = %e,
                "Failed to encode ticket"
            );
            e
        })
    }

    /// Parse a ticket from a compressed string.
    pub fn parse(s: String) -> anyhow::Result<Self> {
        let s = hash::expand_string(s)
            .map_err(|e| {
                error!(
                    event = "ticket_decode_failure",
                    error = %e,
                    "Failed to decompress ticket"
                );
                e
            })
            .context("failed to decompress ticket")?;

        let ticket: Self = serde_json::from_str(&s).map_err(|e| {
            error!(
                event = "ticket_deserialize_failure",
                error = %e,
                "Failed to deserialize ticket"
            );
            anyhow::anyhow!(e)
        }).context("failed to deserialize ticket")?;

        Ok(ticket)
    }
}
