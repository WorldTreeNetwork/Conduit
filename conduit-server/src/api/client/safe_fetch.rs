//! SSRF-safe outbound HTTP fetches (URL previews, redirected remote media).
//!
//! The homeserver fetches URLs chosen by users and remote servers, so every
//! hop is checked before a socket opens:
//!
//! * only `http`/`https` URLs;
//! * IP-literal hosts are classified directly;
//! * hostnames are resolved here and the request is refused when **any**
//!   resolved address is denied; the connection itself goes through a
//!   resolver that re-applies the same check (no DNS-rebinding window);
//! * the peer address of the established connection is checked once more;
//! * redirects are followed manually (each hop re-validated), bounded;
//! * bodies are size-capped while streaming and the whole fetch is bounded
//!   by one deadline;
//! * environment proxies are ignored.
//!
//! Denied: loopback, RFC 1918 private, link-local, CGNAT (100.64/10),
//! multicast, broadcast/reserved, documentation and benchmarking ranges,
//! "this network", IPv6 unique-local, site-local, link-local, multicast,
//! discard-only, IETF-protocol (incl. Teredo), IPv4-mapped and
//! IPv4-compatible addresses, and NAT64/6to4 addresses that embed a denied
//! IPv4 address. An operator allowlist of CIDRs overrides the denylist.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use url::Url;

/// A CIDR block, e.g. `10.0.0.0/8` or `fd00::/8`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cidr {
    network: IpAddr,
    prefix: u8,
}

impl Cidr {
    pub fn parse(s: &str) -> Option<Self> {
        let s = s.trim();
        let (addr, prefix) = match s.split_once('/') {
            Some((a, p)) => (a, Some(p)),
            None => (s, None),
        };
        let network: IpAddr = addr.trim().parse().ok()?;
        let max = if network.is_ipv4() { 32 } else { 128 };
        let prefix = match prefix {
            Some(p) => p.trim().parse::<u8>().ok().filter(|p| *p <= max)?,
            None => max,
        };
        Some(Self { network, prefix })
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.network, ip) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                prefix_match(&net.octets(), &ip.octets(), self.prefix)
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                prefix_match(&net.octets(), &ip.octets(), self.prefix)
            }
            _ => false,
        }
    }
}

fn prefix_match(a: &[u8], b: &[u8], prefix: u8) -> bool {
    let full = (prefix / 8) as usize;
    if a[..full] != b[..full] {
        return false;
    }
    let rem = prefix % 8;
    if rem == 0 {
        return true;
    }
    let mask = 0xffu8 << (8 - rem);
    (a[full] & mask) == (b[full] & mask)
}

/// Parse a comma/space separated CIDR list; invalid entries are skipped.
pub fn parse_cidr_list(s: &str) -> Vec<Cidr> {
    s.split(|c: char| c == ',' || c.is_whitespace())
        .filter(|p| !p.is_empty())
        .filter_map(|p| {
            let parsed = Cidr::parse(p);
            if parsed.is_none() {
                tracing::warn!(entry = p, "ignoring invalid CIDR in allowlist");
            }
            parsed
        })
        .collect()
}

fn v4_denied(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    o[0] == 0                                         // 0.0.0.0/8 "this network"
        || o[0] == 10                                 // 10/8 private
        || (o[0] == 100 && (o[1] & 0xc0) == 64)       // 100.64/10 CGNAT
        || o[0] == 127                                // loopback
        || (o[0] == 169 && o[1] == 254)               // link-local (cloud metadata)
        || (o[0] == 172 && (o[1] & 0xf0) == 16)       // 172.16/12 private
        || (o[0] == 192 && o[1] == 0 && o[2] == 0)    // 192.0.0/24 IETF
        || (o[0] == 192 && o[1] == 0 && o[2] == 2)    // TEST-NET-1
        || (o[0] == 192 && o[1] == 88 && o[2] == 99)  // 6to4 relay anycast
        || (o[0] == 192 && o[1] == 168)               // 192.168/16 private
        || (o[0] == 198 && (o[1] & 0xfe) == 18)       // 198.18/15 benchmarking
        || (o[0] == 198 && o[1] == 51 && o[2] == 100) // TEST-NET-2
        || (o[0] == 203 && o[1] == 0 && o[2] == 113)  // TEST-NET-3
        || o[0] >= 224 // 224/4 multicast, 240/4 reserved, broadcast
}

fn v6_denied(ip: Ipv6Addr) -> bool {
    let s = ip.segments();
    // ::/96 covers ::, ::1 and deprecated IPv4-compatible addresses;
    // ::ffff:0:0/96 is IPv4-mapped. Both are refused outright: mapped
    // addresses are a classic filter bypass.
    if s[0..5] == [0, 0, 0, 0, 0] && (s[5] == 0 || s[5] == 0xffff) {
        return true;
    }
    // 64:ff9b::/96 well-known NAT64: judge the embedded IPv4 address.
    if s[0..6] == [0x64, 0xff9b, 0, 0, 0, 0] {
        return v4_denied(embedded_v4(s[6], s[7]));
    }
    // 64:ff9b:1::/48 local-use NAT64.
    if s[0] == 0x64 && s[1] == 0xff9b && s[2] == 1 {
        return true;
    }
    // 100::/64 discard-only.
    if s[0..4] == [0x100, 0, 0, 0] {
        return true;
    }
    // 2001::/23 IETF protocol assignments (Teredo, ORCHID, ...).
    if s[0] == 0x2001 && s[1] < 0x200 {
        return true;
    }
    // 2001:db8::/32 documentation.
    if s[0] == 0x2001 && s[1] == 0xdb8 {
        return true;
    }
    // 2002::/16 6to4: judge the embedded IPv4 address.
    if s[0] == 0x2002 {
        return v4_denied(embedded_v4(s[1], s[2]));
    }
    (s[0] & 0xfe00) == 0xfc00          // fc00::/7 unique local
        || (s[0] & 0xffc0) == 0xfe80   // fe80::/10 link-local
        || (s[0] & 0xffc0) == 0xfec0   // fec0::/10 site-local
        || (s[0] & 0xff00) == 0xff00 // ff00::/8 multicast
}

fn embedded_v4(hi: u16, lo: u16) -> Ipv4Addr {
    Ipv4Addr::new((hi >> 8) as u8, hi as u8, (lo >> 8) as u8, lo as u8)
}

/// True when the address must never be contacted (before allowlisting).
pub fn ip_is_denied(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4_denied(v4),
        IpAddr::V6(v6) => v6_denied(v6),
    }
}

/// Outbound fetch limits and allowlist.
#[derive(Debug, Clone)]
pub struct FetchPolicy {
    /// CIDRs exempt from the denylist (operator opt-in, e.g. an intranet).
    pub allow: Vec<Cidr>,
    pub max_bytes: usize,
    pub timeout: Duration,
    pub max_redirects: usize,
}

impl FetchPolicy {
    pub fn permits(&self, ip: IpAddr) -> bool {
        !ip_is_denied(ip) || self.allow.iter().any(|c| c.contains(ip))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FetchError {
    /// Not an absolute http(s) URL.
    InvalidUrl(String),
    /// The destination resolves to a denied address.
    Blocked(String),
    /// The body (or declared length) exceeds `max_bytes`.
    TooLarge,
    TimedOut,
    /// Connection, protocol or non-success status failures.
    Upstream(String),
}

impl std::fmt::Display for FetchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FetchError::InvalidUrl(m) => write!(f, "invalid URL: {m}"),
            FetchError::Blocked(m) => write!(f, "destination not permitted: {m}"),
            FetchError::TooLarge => write!(f, "response exceeds the size limit"),
            FetchError::TimedOut => write!(f, "fetch timed out"),
            FetchError::Upstream(m) => write!(f, "fetch failed: {m}"),
        }
    }
}

/// A completed fetch.
#[derive(Debug, Clone)]
pub struct Fetched {
    pub final_url: Url,
    pub content_type: Option<String>,
    pub content_disposition: Option<String>,
    pub body: Vec<u8>,
}

/// Resolver handed to reqwest: the connection only ever targets addresses
/// that passed the policy, even if DNS answers change between our check
/// and the connect.
struct PolicyResolver {
    policy: Arc<FetchPolicy>,
}

#[derive(Debug)]
struct BlockedAddress(String);
impl std::fmt::Display for BlockedAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} resolves to a denied address", self.0)
    }
}
impl std::error::Error for BlockedAddress {}

impl reqwest::dns::Resolve for PolicyResolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let policy = Arc::clone(&self.policy);
        let host = name.as_str().to_owned();
        Box::pin(async move {
            let addrs = resolve_checked(&policy, &host, 0)
                .await
                .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> {
                    Box::new(BlockedAddress(e.to_string()))
                })?;
            Ok(Box::new(addrs.into_iter()) as reqwest::dns::Addrs)
        })
    }
}

/// Resolve `host` and fail closed if any address is denied.
async fn resolve_checked(
    policy: &FetchPolicy,
    host: &str,
    port: u16,
) -> Result<Vec<SocketAddr>, FetchError> {
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host, port))
        .await
        .map_err(|e| FetchError::Upstream(format!("DNS lookup for {host} failed: {e}")))?
        .collect();
    if addrs.is_empty() {
        return Err(FetchError::Upstream(format!("{host} has no addresses")));
    }
    if let Some(bad) = addrs.iter().find(|a| !policy.permits(a.ip())) {
        return Err(FetchError::Blocked(format!("{host} resolves to {}", bad.ip())));
    }
    Ok(addrs)
}

fn build_client(policy: &Arc<FetchPolicy>) -> Result<reqwest::Client, FetchError> {
    reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(policy.timeout)
        .timeout(policy.timeout)
        .user_agent(concat!("Conduit/", env!("CARGO_PKG_VERSION"), " (URL preview)"))
        .dns_resolver(Arc::new(PolicyResolver { policy: Arc::clone(policy) }))
        .build()
        .map_err(|e| FetchError::Upstream(format!("client build failed: {e}")))
}

/// Validate one hop's URL: scheme, host, and IP-literal policy.
pub async fn check_url(policy: &FetchPolicy, url: &Url) -> Result<(), FetchError> {
    match url.scheme() {
        "http" | "https" => {}
        other => return Err(FetchError::InvalidUrl(format!("unsupported scheme {other}"))),
    }
    match url.host() {
        None => Err(FetchError::InvalidUrl("URL has no host".into())),
        Some(url::Host::Ipv4(ip)) => {
            if policy.permits(IpAddr::V4(ip)) {
                Ok(())
            } else {
                Err(FetchError::Blocked(format!("address {ip}")))
            }
        }
        Some(url::Host::Ipv6(ip)) => {
            if policy.permits(IpAddr::V6(ip)) {
                Ok(())
            } else {
                Err(FetchError::Blocked(format!("address {ip}")))
            }
        }
        Some(url::Host::Domain(domain)) => {
            let port = url.port_or_known_default().unwrap_or(80);
            resolve_checked(policy, domain, port).await.map(|_| ())
        }
    }
}

fn is_blocked_error(e: &reqwest::Error) -> Option<String> {
    let mut source: Option<&(dyn std::error::Error + 'static)> = Some(e);
    while let Some(err) = source {
        if let Some(b) = err.downcast_ref::<BlockedAddress>() {
            return Some(b.0.clone());
        }
        source = err.source();
    }
    None
}

/// GET `url` under `policy`, following up to `max_redirects` redirects.
pub async fn fetch(policy: Arc<FetchPolicy>, url: &str) -> Result<Fetched, FetchError> {
    let mut current = Url::parse(url).map_err(|e| FetchError::InvalidUrl(e.to_string()))?;
    current.set_fragment(None);
    let deadline = policy.timeout;
    match tokio::time::timeout(deadline, fetch_inner(policy, current)).await {
        Ok(result) => result,
        Err(_) => Err(FetchError::TimedOut),
    }
}

async fn fetch_inner(policy: Arc<FetchPolicy>, mut current: Url) -> Result<Fetched, FetchError> {
    let client = build_client(&policy)?;
    let mut hops = 0usize;
    loop {
        check_url(&policy, &current).await?;
        let mut response = client
            .get(current.clone())
            .header(reqwest::header::ACCEPT, "text/html,application/xhtml+xml,image/*;q=0.9,*/*;q=0.5")
            .send()
            .await
            .map_err(|e| {
                if let Some(blocked) = is_blocked_error(&e) {
                    FetchError::Blocked(blocked)
                } else if e.is_timeout() {
                    FetchError::TimedOut
                } else {
                    FetchError::Upstream(e.to_string())
                }
            })?;
        if let Some(peer) = response.remote_addr() {
            if !policy.permits(peer.ip()) {
                return Err(FetchError::Blocked(format!("connected peer {}", peer.ip())));
            }
        }
        let status = response.status();
        if status.is_redirection() {
            let location = response
                .headers()
                .get(reqwest::header::LOCATION)
                .and_then(|v| v.to_str().ok())
                .ok_or_else(|| FetchError::Upstream(format!("{status} without Location")))?;
            hops += 1;
            if hops > policy.max_redirects {
                return Err(FetchError::Upstream("too many redirects".into()));
            }
            let mut next = current
                .join(location)
                .map_err(|e| FetchError::InvalidUrl(format!("bad redirect: {e}")))?;
            next.set_fragment(None);
            current = next;
            continue;
        }
        if !status.is_success() {
            return Err(FetchError::Upstream(format!("upstream returned {status}")));
        }
        if let Some(len) = response.content_length() {
            if len > policy.max_bytes as u64 {
                return Err(FetchError::TooLarge);
            }
        }
        let header = |name: reqwest::header::HeaderName| {
            response
                .headers()
                .get(name)
                .and_then(|v| v.to_str().ok())
                .map(str::to_owned)
        };
        let content_type = header(reqwest::header::CONTENT_TYPE);
        let content_disposition = header(reqwest::header::CONTENT_DISPOSITION);
        let mut body = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|e| if e.is_timeout() { FetchError::TimedOut } else { FetchError::Upstream(e.to_string()) })?
        {
            if body.len() + chunk.len() > policy.max_bytes {
                return Err(FetchError::TooLarge);
            }
            body.extend_from_slice(&chunk);
        }
        return Ok(Fetched {
            final_url: current,
            content_type,
            content_disposition,
            body,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn denied(s: &str) -> bool {
        ip_is_denied(s.parse().unwrap())
    }

    #[test]
    fn denies_internal_ipv4_ranges() {
        for ip in [
            "0.0.0.0", "10.1.2.3", "100.64.0.1", "100.127.255.254", "127.0.0.1",
            "127.255.255.255", "169.254.169.254", "172.16.0.1", "172.31.255.255",
            "192.0.0.8", "192.0.2.1", "192.168.1.1", "198.18.0.1", "198.19.255.255",
            "198.51.100.7", "203.0.113.9", "224.0.0.1", "239.255.255.250",
            "240.0.0.1", "255.255.255.255",
        ] {
            assert!(denied(ip), "{ip} must be denied");
        }
    }

    #[test]
    fn allows_public_ipv4() {
        for ip in ["1.1.1.1", "8.8.8.8", "100.63.255.255", "100.128.0.1", "172.15.0.1", "172.32.0.1", "93.184.216.34"] {
            assert!(!denied(ip), "{ip} must be allowed");
        }
    }

    #[test]
    fn denies_internal_and_mapped_ipv6() {
        for ip in [
            "::", "::1", "::ffff:127.0.0.1", "::ffff:8.8.8.8", "::127.0.0.1",
            "fc00::1", "fd12:3456::1", "fe80::1", "fec0::1", "ff02::1",
            "100::1", "2001::1", "2001:db8::1", "64:ff9b::7f00:1", "64:ff9b::a00:1",
            "64:ff9b:1::1", "2002:7f00:1::1", "2002:a9fe:a9fe::1",
        ] {
            assert!(denied(ip), "{ip} must be denied");
        }
    }

    #[test]
    fn allows_public_ipv6() {
        for ip in ["2606:4700:4700::1111", "2001:4860:4860::8888", "64:ff9b::808:808", "2002:808:808::1"] {
            assert!(!denied(ip), "{ip} must be allowed");
        }
    }

    #[test]
    fn cidr_allowlist_overrides_only_listed_ranges() {
        let policy = FetchPolicy {
            allow: parse_cidr_list("127.0.0.1/32, 10.0.0.0/8 bogus fd00::/8"),
            max_bytes: 1,
            timeout: Duration::from_secs(1),
            max_redirects: 1,
        };
        assert_eq!(policy.allow.len(), 3);
        assert!(policy.permits("127.0.0.1".parse().unwrap()));
        assert!(!policy.permits("127.0.0.2".parse().unwrap()));
        assert!(policy.permits("10.9.9.9".parse().unwrap()));
        assert!(policy.permits("fd00::5".parse().unwrap()));
        // An IPv4 allow entry never admits the IPv4-mapped IPv6 spelling.
        assert!(!policy.permits("::ffff:127.0.0.1".parse().unwrap()));
        assert!(!policy.permits("169.254.169.254".parse().unwrap()));
        assert!(policy.permits("8.8.8.8".parse().unwrap()));
    }

    #[test]
    fn cidr_parse_edges() {
        assert!(Cidr::parse("1.2.3.4/33").is_none());
        assert!(Cidr::parse("::/129").is_none());
        assert!(Cidr::parse("nope").is_none());
        let c = Cidr::parse("100.64.0.0/10").unwrap();
        assert!(c.contains("100.127.0.1".parse().unwrap()));
        assert!(!c.contains("100.128.0.1".parse().unwrap()));
        assert!(Cidr::parse("0.0.0.0/0").unwrap().contains("9.9.9.9".parse().unwrap()));
    }

    #[tokio::test]
    async fn literal_and_resolved_hosts_are_checked_before_connecting() {
        let policy = FetchPolicy {
            allow: vec![],
            max_bytes: 1024,
            timeout: Duration::from_secs(2),
            max_redirects: 2,
        };
        for url in [
            "http://127.0.0.1:9/",
            "http://[::1]:9/",
            "http://[::ffff:127.0.0.1]:9/",
            "http://169.254.169.254/latest/meta-data/",
            "http://localhost:9/",
            "http://0x7f.1/",
            "http://2130706433/",
        ] {
            let err = fetch(Arc::new(policy.clone()), url).await.unwrap_err();
            assert!(matches!(err, FetchError::Blocked(_)), "{url}: {err:?}");
        }
        let err = fetch(Arc::new(policy.clone()), "file:///etc/passwd").await.unwrap_err();
        assert!(matches!(err, FetchError::InvalidUrl(_)), "{err:?}");
        let err = fetch(Arc::new(policy), "gopher://example.org/").await.unwrap_err();
        assert!(matches!(err, FetchError::InvalidUrl(_)), "{err:?}");
    }
}
