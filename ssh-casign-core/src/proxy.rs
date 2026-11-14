//! Where a request came from, behind reverse proxies, load balancers and
//! CDNs: the client address from a forwarding header, the proxy that
//! delivered it, and the proxy's correlation ID (e.g. Cloudflare's `CF-Ray`).
//!
//! Without `trusted_proxies`, a configured header is believed from every
//! peer. That suits platforms where the proxy can't be bypassed (Lambda,
//! Cloud Run, Azure Functions). With it, the header is only used when the TCP
//! peer is a trusted proxy, and trusted addresses at the end of the header
//! are skipped, so the first address no trusted proxy vouches for is the
//! client.

use std::net::{IpAddr, SocketAddr};

use axum::http::HeaderMap;

/// Longest correlation ID that is recorded; longer values are cut.
const MAX_CORRELATION_ID: usize = 128;

/// An address range, `192.0.2.0/24` or `2001:db8::/32`; a bare address is a
/// single host.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Cidr {
    network: IpAddr,
    prefix: u8,
}

impl Cidr {
    pub(crate) fn parse(text: &str) -> Result<Self, String> {
        let text = text.trim();
        let (address, prefix) = match text.split_once('/') {
            Some((address, prefix)) => (address, Some(prefix)),
            None => (text, None),
        };
        let network: IpAddr = address
            .parse()
            .map_err(|_| format!("'{text}' is not an address or address range"))?;
        let max = if network.is_ipv4() { 32 } else { 128 };
        let prefix = match prefix {
            Some(prefix) => prefix
                .parse::<u8>()
                .ok()
                .filter(|prefix| *prefix <= max)
                .ok_or_else(|| format!("'{text}': invalid prefix length"))?,
            None => max,
        };
        if Self::mask(network, prefix) != network {
            return Err(format!("'{text}': host bits set after the prefix"));
        }
        Ok(Self { network, prefix })
    }

    fn mask(address: IpAddr, prefix: u8) -> IpAddr {
        match address {
            IpAddr::V4(v4) => {
                let bits = u32::from(v4);
                let mask = u32::MAX.checked_shl(32 - u32::from(prefix)).unwrap_or(0);
                IpAddr::V4((bits & mask).into())
            }
            IpAddr::V6(v6) => {
                let bits = u128::from(v6);
                let mask = u128::MAX.checked_shl(128 - u32::from(prefix)).unwrap_or(0);
                IpAddr::V6((bits & mask).into())
            }
        }
    }

    pub(crate) fn contains(&self, address: IpAddr) -> bool {
        let address = address.to_canonical();
        address.is_ipv4() == self.network.is_ipv4()
            && Self::mask(address, self.prefix) == self.network
    }
}

/// Settings from `[audit]`.
#[derive(Default)]
pub(crate) struct Settings<'a> {
    pub(crate) header: Option<&'a str>,
    pub(crate) skip: usize,
    pub(crate) trusted_proxies: Option<&'a [String]>,
    pub(crate) correlation_id_header: Option<&'a str>,
}

/// Resolves a request's origin; built once from the configuration.
#[derive(Default)]
pub(crate) struct Resolver {
    header: Option<String>,
    skip: usize,
    /// `None`: every peer is trusted.
    trusted: Option<Vec<Cidr>>,
    correlation_id_header: Option<String>,
}

/// Where a request came from.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Origin {
    pub(crate) client_ip: IpAddr,
    /// The TCP port, when the client is the TCP peer.
    pub(crate) client_port: Option<u16>,
    /// The TCP peer, when the client address came from a header.
    pub(crate) proxy: Option<SocketAddr>,
    /// The trusted proxy's request ID.
    pub(crate) correlation_id: Option<String>,
}

impl Resolver {
    pub(crate) fn new(settings: Settings<'_>) -> Result<Self, String> {
        let trusted = settings
            .trusted_proxies
            .map(|ranges| {
                ranges
                    .iter()
                    .map(|range| {
                        Cidr::parse(range).map_err(|err| format!("trusted_proxies: {err}"))
                    })
                    .collect::<Result<Vec<_>, _>>()
            })
            .transpose()?;
        let lowercase = |name: &str| name.trim().to_ascii_lowercase();
        let resolver = Self {
            header: settings.header.map(lowercase),
            skip: settings.skip,
            trusted,
            correlation_id_header: settings.correlation_id_header.map(lowercase),
        };
        if resolver.trusted.is_none()
            && (resolver.header.is_some() || resolver.correlation_id_header.is_some())
        {
            tracing::warn!(
                "audit: forwarding headers are believed from every peer; set trusted_proxies \
                 unless clients can only reach the service through the proxy"
            );
        }
        Ok(resolver)
    }

    fn trusts(&self, address: IpAddr) -> bool {
        match &self.trusted {
            None => true,
            Some(ranges) => ranges.iter().any(|range| range.contains(address)),
        }
    }

    /// Ranges are configured and contain `address`.
    fn is_trusted_hop(&self, address: IpAddr) -> bool {
        self.trusted
            .as_ref()
            .is_some_and(|ranges| ranges.iter().any(|range| range.contains(address)))
    }

    pub(crate) fn resolve(&self, peer: SocketAddr, headers: &HeaderMap) -> Origin {
        let peer = SocketAddr::new(peer.ip().to_canonical(), peer.port());
        let direct = Origin {
            client_ip: peer.ip(),
            client_port: Some(peer.port()),
            proxy: None,
            correlation_id: None,
        };
        if !self.trusts(peer.ip()) {
            return direct;
        }
        let correlation_id = self
            .correlation_id_header
            .as_deref()
            .and_then(|name| correlation_id(headers, name));
        let client_ip = self
            .header
            .as_deref()
            .and_then(|name| self.client_from_header(headers, name));
        match client_ip {
            Some(client_ip) => Origin {
                client_ip,
                client_port: None,
                proxy: Some(peer),
                correlation_id,
            },
            None => Origin {
                correlation_id,
                ..direct
            },
        }
    }

    /// Walk the header from the right: skip `skip` entries (proxies whose
    /// addresses aren't known), then trusted proxies; the next address is the
    /// client. An entry that isn't an address (`unknown`, an obfuscated
    /// identifier, garbage) ends the walk: the last hop that could be trusted
    /// is recorded instead. `None` means the header gives nothing usable.
    fn client_from_header(&self, headers: &HeaderMap, name: &str) -> Option<IpAddr> {
        let entries = header_entries(headers, name);
        if entries.len() <= self.skip {
            // Fewer entries than the proxies add: the proxy was bypassed.
            return None;
        }
        let mut last = None;
        for (index, entry) in entries.iter().rev().enumerate() {
            let Some(address) = entry.as_deref().and_then(parse_node) else {
                // `None` without an earlier hop: the peer itself.
                return last;
            };
            if index < self.skip || self.is_trusted_hop(address) {
                last = Some(address);
                continue;
            }
            return Some(address);
        }
        // Every entry is a trusted proxy: the leftmost is the best we know.
        last
    }
}

/// The node identifiers in `name`, in order. Several header lines count as
/// one list. For `Forwarded` (RFC 7239), the `for=` parameter of each element
/// (`None` when an element has none).
fn header_entries(headers: &HeaderMap, name: &str) -> Vec<Option<String>> {
    let forwarded = name == "forwarded";
    headers
        .get_all(name)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .map(|element| {
            if forwarded {
                element.split(';').find_map(|pair| {
                    let (key, value) = pair.split_once('=')?;
                    key.trim()
                        .eq_ignore_ascii_case("for")
                        .then(|| value.trim().trim_matches('"').to_string())
                })
            } else {
                Some(element.trim().to_string())
            }
        })
        .collect()
}

/// An address with or without a port: `192.0.2.1`, `192.0.2.1:443`,
/// `2001:db8::1`, `[2001:db8::1]` or `[2001:db8::1]:443`.
fn parse_node(node: &str) -> Option<IpAddr> {
    let node = node.trim();
    if let Ok(address) = node.parse::<IpAddr>() {
        return Some(address.to_canonical());
    }
    if let Ok(address) = node.parse::<SocketAddr>() {
        return Some(address.ip().to_canonical());
    }
    node.strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
        .and_then(|inner| inner.parse::<IpAddr>().ok())
        .map(|address| address.to_canonical())
}

/// A proxy's request ID, limited to printable ASCII without spaces.
fn correlation_id(headers: &HeaderMap, name: &str) -> Option<String> {
    let value = headers.get(name)?.to_str().ok()?.trim();
    let value: String = value
        .chars()
        .filter(|c| c.is_ascii_graphic())
        .take(MAX_CORRELATION_ID)
        .collect();
    (!value.is_empty()).then_some(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    const PEER: &str = "10.0.0.1:443";

    fn resolver(header: &str, skip: usize, trusted: Option<&[&str]>) -> Resolver {
        let trusted: Option<Vec<String>> =
            trusted.map(|ranges| ranges.iter().map(|range| range.to_string()).collect());
        Resolver::new(Settings {
            header: Some(header),
            skip,
            trusted_proxies: trusted.as_deref(),
            correlation_id_header: Some("CF-Ray"),
        })
        .unwrap()
    }

    fn headers(pairs: &[(&'static str, &str)]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for (name, value) in pairs {
            headers.append(*name, value.parse().unwrap());
        }
        headers
    }

    /// The client address, and whether it came from the header.
    fn client(resolver: &Resolver, pairs: &[(&'static str, &str)]) -> (String, bool) {
        let origin = resolver.resolve(PEER.parse().unwrap(), &headers(pairs));
        assert_eq!(origin.proxy.is_some(), origin.client_port.is_none());
        (origin.client_ip.to_string(), origin.proxy.is_some())
    }

    fn from_header(ip: &str) -> (String, bool) {
        (ip.to_string(), true)
    }

    fn from_peer() -> (String, bool) {
        ("10.0.0.1".to_string(), false)
    }

    #[test]
    fn cidr() {
        let range = Cidr::parse("192.0.2.0/24").unwrap();
        assert!(range.contains("192.0.2.200".parse().unwrap()));
        assert!(!range.contains("192.0.3.1".parse().unwrap()));
        assert!(range.contains("::ffff:192.0.2.1".parse().unwrap()));
        assert!(!range.contains("2001:db8::1".parse().unwrap()));
        let v6 = Cidr::parse("2400:cb00::/32").unwrap();
        assert!(v6.contains("2400:cb00:1::7".parse().unwrap()));
        assert!(!v6.contains("2400:cb01::7".parse().unwrap()));
        assert!(Cidr::parse("0.0.0.0/0")
            .unwrap()
            .contains("203.0.113.1".parse().unwrap()));
        assert!(Cidr::parse("127.0.0.1")
            .unwrap()
            .contains("127.0.0.1".parse().unwrap()));
        for bad in [
            "192.0.2.1/24",
            "192.0.2.0/33",
            "::/129",
            "example.com",
            "1.2.3.4/x",
        ] {
            assert!(Cidr::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn untrusted_peer_ignores_headers() {
        let resolver = resolver("x-forwarded-for", 0, Some(&["192.0.2.0/24"]));
        let origin = resolver.resolve(
            PEER.parse().unwrap(),
            &headers(&[("x-forwarded-for", "203.0.113.9"), ("cf-ray", "abc-AMS")]),
        );
        assert_eq!(
            origin,
            Origin {
                client_ip: "10.0.0.1".parse().unwrap(),
                client_port: Some(443),
                proxy: None,
                correlation_id: None,
            }
        );
    }

    #[test]
    fn trusted_peer_and_correlation_id() {
        let resolver = resolver("cf-connecting-ip", 0, Some(&["10.0.0.0/8"]));
        let origin = resolver.resolve(
            PEER.parse().unwrap(),
            &headers(&[
                ("cf-connecting-ip", "2001:db8::7"),
                ("cf-ray", "8f1c2a3b4c5d6e7f-AMS"),
            ]),
        );
        assert_eq!(
            origin,
            Origin {
                client_ip: "2001:db8::7".parse().unwrap(),
                client_port: None,
                proxy: Some(PEER.parse().unwrap()),
                correlation_id: Some("8f1c2a3b4c5d6e7f-AMS".into()),
            }
        );
        // No header: the peer, but still the proxy's request ID.
        let origin = resolver.resolve(PEER.parse().unwrap(), &headers(&[("cf-ray", "x y\tz")]));
        assert_eq!(origin.client_port, Some(443));
        assert_eq!(origin.correlation_id.as_deref(), Some("xyz"));
        let long = "a".repeat(500);
        let origin = resolver.resolve(PEER.parse().unwrap(), &headers(&[("cf-ray", &long)]));
        assert_eq!(origin.correlation_id.unwrap().len(), MAX_CORRELATION_ID);
    }

    #[test]
    fn ipv4_mapped_peer_is_trusted() {
        let resolver = resolver("x-real-ip", 0, Some(&["127.0.0.1"]));
        let origin = resolver.resolve(
            "[::ffff:127.0.0.1]:5000".parse().unwrap(),
            &headers(&[("x-real-ip", "203.0.113.9")]),
        );
        assert_eq!(origin.client_ip, "203.0.113.9".parse::<IpAddr>().unwrap());
        assert_eq!(origin.proxy, Some("127.0.0.1:5000".parse().unwrap()));
    }

    #[test]
    fn walks_past_trusted_proxies() {
        let resolver = resolver(
            "x-forwarded-for",
            0,
            Some(&["10.0.0.0/8", "198.51.100.0/24"]),
        );
        // Spoofed entry left of the client, then two trusted hops.
        let chain = "6.6.6.6, 203.0.113.9, 198.51.100.2, 10.1.2.3";
        assert_eq!(
            client(&resolver, &[("x-forwarded-for", chain)]),
            from_header("203.0.113.9")
        );
        // Several header lines are one list.
        assert_eq!(
            client(
                &resolver,
                &[
                    ("x-forwarded-for", "6.6.6.6, 203.0.113.9"),
                    ("x-forwarded-for", "10.1.2.3")
                ]
            ),
            from_header("203.0.113.9")
        );
        // Only trusted hops: the leftmost.
        assert_eq!(
            client(&resolver, &[("x-forwarded-for", "10.9.9.9, 198.51.100.2")]),
            from_header("10.9.9.9")
        );
        // An entry that isn't an address stops the walk at the last trusted hop.
        assert_eq!(
            client(
                &resolver,
                &[("x-forwarded-for", "203.0.113.9, unknown, 198.51.100.2")]
            ),
            from_header("198.51.100.2")
        );
        assert_eq!(
            client(&resolver, &[("x-forwarded-for", "garbage")]),
            from_peer()
        );
        assert_eq!(client(&resolver, &[]), from_peer());
    }

    #[test]
    fn without_trusted_proxies() {
        let resolver = resolver("X-Forwarded-For", 0, None);
        assert_eq!(client(&resolver, &[]), from_peer());
        assert_eq!(
            client(
                &resolver,
                &[("x-forwarded-for", "203.0.113.9, 198.51.100.2")]
            ),
            from_header("198.51.100.2")
        );
        // Azure adds "IP:port".
        assert_eq!(
            client(&resolver, &[("x-forwarded-for", "203.0.113.9:54321")]),
            from_header("203.0.113.9")
        );
        assert_eq!(
            client(&resolver, &[("x-forwarded-for", "[2001:db8::7]:443")]),
            from_header("2001:db8::7")
        );
        assert_eq!(
            client(&resolver, &[("x-forwarded-for", "garbage")]),
            from_peer()
        );
    }

    #[test]
    fn skip() {
        let resolver = resolver("x-forwarded-for", 1, None);
        let chain = "198.51.100.66, 203.0.113.9, 130.211.0.1";
        assert_eq!(
            client(&resolver, &[("x-forwarded-for", chain)]),
            from_header("203.0.113.9")
        );
        // Fewer entries than expected: the proxy was bypassed.
        assert_eq!(
            client(&resolver, &[("x-forwarded-for", "203.0.113.9")]),
            from_peer()
        );
        let resolver_5 = super::Resolver {
            skip: 5,
            ..resolver
        };
        assert_eq!(
            client(&resolver_5, &[("x-forwarded-for", chain)]),
            from_peer()
        );
        // Skip and trusted proxies together: a CDN behind a load balancer.
        let resolver = resolver_with_skip_and_trust();
        assert_eq!(
            client(
                &resolver,
                &[(
                    "x-forwarded-for",
                    "6.6.6.6, 203.0.113.9, 173.245.48.1, 130.211.0.1"
                )]
            ),
            from_header("203.0.113.9")
        );
    }

    fn resolver_with_skip_and_trust() -> Resolver {
        resolver(
            "x-forwarded-for",
            1,
            Some(&["10.0.0.0/8", "173.245.48.0/20"]),
        )
    }

    #[test]
    fn rfc7239_forwarded() {
        let resolver = resolver("Forwarded", 0, Some(&["10.0.0.0/8"]));
        let value =
            r#"for=6.6.6.6, for="[2001:db8::7]:4711";proto=https, by=10.0.0.1;For=10.2.3.4"#;
        assert_eq!(
            client(&resolver, &[("forwarded", value)]),
            from_header("2001:db8::7")
        );
        assert_eq!(
            client(
                &resolver,
                &[("forwarded", "for=192.0.2.60;proto=http;by=203.0.113.43")]
            ),
            from_header("192.0.2.60")
        );
        // "unknown", obfuscated identifiers and elements without for=: stop.
        assert_eq!(
            client(&resolver, &[("forwarded", "for=unknown")]),
            from_peer()
        );
        assert_eq!(
            client(
                &resolver,
                &[("forwarded", "for=192.0.2.60, for=_hidden, for=10.0.0.9")]
            ),
            from_header("10.0.0.9")
        );
        assert_eq!(
            client(&resolver, &[("forwarded", "proto=https")]),
            from_peer()
        );
    }

    #[test]
    fn invalid_trusted_proxies() {
        let ranges = vec!["10.0.0.0/8".to_string(), "nope".to_string()];
        let err = Resolver::new(Settings {
            trusted_proxies: Some(&ranges),
            ..Settings::default()
        })
        .err()
        .unwrap();
        assert!(
            err.contains("trusted_proxies") && err.contains("nope"),
            "{err}"
        );
    }
}
