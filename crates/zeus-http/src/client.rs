//! Configuration of the production transport and the user-agent policy.

use std::time::Duration;

use zeus_types::policy::scheduling::{CONNECT_TIMEOUT_MS, READ_TIMEOUT_MS};

/// How Zeus identifies itself when no session user agent is in use.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum UserAgentPolicy {
    /// `Zeus/<version> (+https://github.com/ArefinAlter/zeus)`. The default for direct requests without
    /// a session: honest about being an automated client.
    #[default]
    Zeus,
    /// A fixed string supplied by configuration.
    Custom(String),
}

impl UserAgentPolicy {
    /// The header value. With session material the browser's own user agent is used instead
    /// (02 section 8.1): session cookies are bound to the browser that created them.
    #[must_use]
    pub fn value(&self) -> String {
        match self {
            Self::Zeus => format!(
                "Zeus/{} (+https://github.com/ArefinAlter/zeus)",
                env!("CARGO_PKG_VERSION")
            ),
            Self::Custom(s) => s.clone(),
        }
    }
}

/// Proxy selection.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum ProxyConfig {
    /// Use the environment and system settings (`HTTP_PROXY`, `HTTPS_PROXY`, `NO_PROXY`, the Windows
    /// and macOS system proxy).
    #[default]
    System,
    /// Never use a proxy.
    None,
    /// A fixed proxy URL.
    Url(String),
}

/// Settings of the production transport.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientConfig {
    /// Connect timeout (default 15 s).
    pub connect_timeout: Duration,
    /// Idle read timeout (default 30 s), enforced between body chunks.
    pub read_timeout: Duration,
    /// Idle connections kept per host.
    pub pool_max_idle_per_host: usize,
    /// How long an idle connection is kept.
    pub pool_idle_timeout: Duration,
    /// Offer HTTP/2 (HTTP/1.1 is always available).
    pub http2: bool,
    /// Proxy selection.
    pub proxy: ProxyConfig,
    /// User-agent policy.
    pub user_agent: UserAgentPolicy,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_millis(CONNECT_TIMEOUT_MS),
            read_timeout: Duration::from_millis(READ_TIMEOUT_MS),
            pool_max_idle_per_host: 8,
            pool_idle_timeout: Duration::from_secs(90),
            http2: true,
            proxy: ProxyConfig::System,
            user_agent: UserAgentPolicy::Zeus,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_match_the_specification() {
        let c = ClientConfig::default();
        assert_eq!(
            (c.connect_timeout, c.read_timeout),
            (Duration::from_secs(15), Duration::from_secs(30))
        );
        assert!(c.user_agent.value().starts_with("Zeus/"));
    }
}
