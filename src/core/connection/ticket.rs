use crate::utils::hash;
use anyhow::Context;
use iroh::EndpointAddr;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct Ticket {
    pub(crate) address: EndpointAddr,
}

impl Ticket {
    pub fn new(endpoint: EndpointAddr) -> Self {
        Self { address: endpoint }
    }

    pub fn export(this: Ticket) -> anyhow::Result<String> {
        hash::compress_string(serde_json::to_string(&this)?)
    }

    pub fn parse(s: String) -> anyhow::Result<Self> {
        let s = hash::expand_string(s).context("failed to decompress ticket")?;
        serde_json::from_str(&s).context("failed to deserialize ticket")
    }
}
