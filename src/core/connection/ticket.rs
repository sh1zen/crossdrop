use crate::utils::hash;
use anyhow::Context;
use iroh::EndpointAddr;
use serde::{Deserialize, Serialize};
use tracing::error;

#[derive(Debug, Serialize, Deserialize)]
pub struct Ticket {
    pub(crate) address: EndpointAddr,
}

impl Ticket {
    pub fn new(endpoint: EndpointAddr) -> Self {
        Self { address: endpoint }
    }

    pub fn export(this: Ticket) -> anyhow::Result<String> {
        hash::compress_string(serde_json::to_string(&this)?).map_err(|e| {
            error!(event = "ticket_encode_failure", error = %e, "Failed to encode ticket");
            e
        })
    }

    pub fn parse(s: String) -> anyhow::Result<Self> {
        let s = hash::expand_string(s)
            .map_err(|e| {
                error!(event = "ticket_decode_failure", error = %e, "Failed to decompress ticket");
                e
            })
            .context("failed to decompress ticket")?;
        let ticket: Self = serde_json::from_str(&s).map_err(|e| {
            error!(event = "ticket_deserialize_failure", error = %e, "Failed to deserialize ticket");
            anyhow::anyhow!(e)
        }).context("failed to deserialize ticket")?;
        Ok(ticket)
    }
}
