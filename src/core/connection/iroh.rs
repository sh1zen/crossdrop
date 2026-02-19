//! Iroh endpoint wrapper for P2P discovery and signaling.
//!
//! Provides:
//! - Endpoint creation with retry logic for port binding
//! - Connection establishment via tickets
//! - Ticket generation for incoming connections

use crate::core::config::PORT_RETRY_ATTEMPTS;
use crate::core::connection::ticket::Ticket;
use crate::workers::args::RelayModeOption;
use anyhow::Context;
use iroh::address_lookup::dns::DnsAddressLookup;
use iroh::address_lookup::pkarr::PkarrPublisher;
use iroh::endpoint::{Connection, Incoming};
use iroh::{Endpoint, SecretKey};
use std::net::{Ipv4Addr, SocketAddrV4};
use std::time::Duration;
use tokio::select;

/// Wrapper around Iroh endpoint for P2P connectivity.
pub struct Iroh {
    endpoint: Option<Endpoint>,
}

impl Iroh {
    /// Create a new Iroh endpoint with the given configuration.
    pub async fn new(
        secret_key: SecretKey,
        relay_mode: RelayModeOption,
        ipv4_addr: Option<std::net::SocketAddrV4>,
        ipv6_addr: Option<std::net::SocketAddrV6>,
        port: u16,
    ) -> anyhow::Result<Self> {
        let endpoint =
            Self::bind_with_retry(secret_key, relay_mode.clone(), ipv4_addr, ipv6_addr, port)
                .await?;

        // Wait for relay connection if enabled
        if !matches!(relay_mode, RelayModeOption::Disabled) {
            Self::wait_for_relay(&endpoint).await?;
        }

        Ok(Self {
            endpoint: Some(endpoint),
        })
    }

    /// Wait for the relay to come online.
    async fn wait_for_relay(endpoint: &Endpoint) -> anyhow::Result<()> {
        let ep = endpoint.clone();
        select! {
            result = tokio::time::timeout(Duration::from_secs(30), async move {
                let _ = ep.online().await;
            }) => result?,
            _ = tokio::signal::ctrl_c() => {
                std::process::exit(130);
            }
        }
        Ok(())
    }

    /// Attempt to bind the endpoint with retry logic for port conflicts.
    async fn try_bind(
        secret_key: SecretKey,
        relay_mode: &RelayModeOption,
        ipv4_addr: Option<std::net::SocketAddrV4>,
        ipv6_addr: Option<std::net::SocketAddrV6>,
        port: u16,
    ) -> anyhow::Result<Endpoint> {
        let mut builder = Endpoint::empty_builder(relay_mode.clone().into())
            .alpns(vec![b"msg/1".to_vec()])
            .secret_key(secret_key)
            .address_lookup(PkarrPublisher::n0_dns())
            .address_lookup(DnsAddressLookup::n0_dns());

        // Configure IPv4 binding
        if let Some(addr) = ipv4_addr {
            let bind_addr = if port > 0 {
                SocketAddrV4::new(*addr.ip(), port)
            } else {
                addr
            };
            builder = builder.bind_addr(bind_addr)?;
        } else if port > 0 {
            builder = builder.bind_addr(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port))?;
        }

        // Configure IPv6 binding
        if let Some(addr) = ipv6_addr {
            builder = builder.bind_addr(addr)?;
        }

        Ok(builder.bind().await?)
    }

    /// Bind endpoint with retry logic for port conflicts.
    async fn bind_with_retry(
        secret_key: SecretKey,
        relay_mode: RelayModeOption,
        ipv4_addr: Option<std::net::SocketAddrV4>,
        ipv6_addr: Option<std::net::SocketAddrV6>,
        port: u16,
    ) -> anyhow::Result<Endpoint> {
        // Port 0 = OS picks a random available port, no retry needed
        if port == 0 {
            return Self::try_bind(secret_key, &relay_mode, ipv4_addr, ipv6_addr, 0).await;
        }

        // Try the requested port, then increment up to PORT_RETRY_ATTEMPTS times
        let mut last_err = None;
        for offset in 0..PORT_RETRY_ATTEMPTS {
            let try_port = port.wrapping_add(offset);
            if try_port == 0 {
                continue; // skip port 0 during iteration
            }

            match Self::try_bind(
                secret_key.clone(),
                &relay_mode,
                ipv4_addr,
                ipv6_addr,
                try_port,
            )
            .await
            {
                Ok(endpoint) => {
                    if offset > 0 {
                        tracing::info!("Port {port} was taken, bound to {try_port} instead");
                    }
                    return Ok(endpoint);
                }
                Err(e) => {
                    if Self::is_port_in_use_error(&e) {
                        tracing::debug!("Port {try_port} in use, trying next...");
                        last_err = Some(e);
                        continue;
                    }
                    // Non-port-conflict error, bail immediately
                    return Err(e);
                }
            }
        }

        // All retries exhausted, fall back to OS-assigned port
        tracing::warn!(
            "Ports {port}-{} all in use, falling back to OS-assigned port",
            port + PORT_RETRY_ATTEMPTS - 1
        );
        Self::try_bind(secret_key, &relay_mode, ipv4_addr, ipv6_addr, 0)
            .await
            .map_err(|e| last_err.unwrap_or(e))
    }

    /// Check if an error indicates a port-in-use condition.
    fn is_port_in_use_error(error: &anyhow::Error) -> bool {
        let msg = format!("{error}");
        msg.contains("in use") || msg.contains("AddrInUse") || msg.contains("address already")
    }

    /// Get a reference to the underlying endpoint.
    pub fn endpoint(&self) -> anyhow::Result<&Endpoint> {
        self.endpoint.as_ref().context("endpoint not prepared")
    }

    /// Connect to a peer using a ticket.
    pub async fn connect(&self, ticket: Ticket) -> anyhow::Result<Connection> {
        let endpoint = self.endpoint()?;

        if ticket.address.relay_urls().next().is_none()
            && ticket.address.ip_addrs().next().is_none()
        {
            tracing::warn!("Ticket has no IP or relay: remote peer may not be reachable");
        }

        endpoint
            .connect(ticket.address, b"msg/1")
            .await
            .context("failed to connect from ticket")
    }

    /// Generate a ticket for this endpoint.
    pub fn ticket(&self) -> anyhow::Result<String> {
        let endpoint = self.endpoint()?;
        let ticket = Ticket::new(endpoint.addr());
        Ticket::export(ticket)
    }

    /// Wait for an incoming connection.
    pub async fn wait_connection(&self) -> anyhow::Result<Incoming> {
        let endpoint = self.endpoint()?;

        match endpoint.accept().await {
            None => anyhow::bail!("endpoint closed unexpectedly"),
            Some(conn) => Ok(conn),
        }
    }
}

impl Drop for Iroh {
    fn drop(&mut self) {
        if let Some(endpoint) = self.endpoint.take() {
            drop(endpoint);
        }
    }
}
