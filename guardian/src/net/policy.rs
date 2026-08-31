use std::{net::IpAddr, sync::LazyLock};

use ipnet::IpNet;
use serde::Deserialize;

static PROTECTED_CIDR_EXCEPTIONS: LazyLock<Vec<IpNet>> = LazyLock::new(|| {
    [
        "0.0.0.0/8",      // This network (RFC 1122)
        "100.64.0.0/10",  // Shared address space (RFC 6598)
        "192.0.0.0/24",   // IETF protocol assignments (RFC 6890)
        "192.88.99.0/24", // Deprecated 6to4 relay anycast (RFC 7526)
        "198.18.0.0/15",  // Benchmarking (RFC 2544)
        "240.0.0.0/4",    // Reserved for future use (RFC 1112)
        "::/96",          // Deprecated IPv4-compatible addresses (RFC 4291)
        "64:ff9b::/96",   // NAT64 well-known prefix (RFC 6052)
        "64:ff9b:1::/48", // Local-use translation prefix (RFC 8215)
        "100::/64",       // Discard-only prefix (RFC 6666)
        "2001::/32",      // Teredo (RFC 4380)
        "2001:2::/48",    // Benchmarking (RFC 5180)
        "2001:10::/28",   // Deprecated ORCHID (RFC 4843)
        "2001:20::/28",   // ORCHIDv2 (RFC 7343)
        "2001:db8::/32",  // Documentation (RFC 3849)
        "2002::/16",      // Deprecated 6to4 (RFC 7526)
        "fec0::/10",      // Deprecated site-local addresses (RFC 3879)
    ]
    .into_iter()
    .map(|v| v.parse().unwrap())
    .collect()
});

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    // Missing sections stay empty rather than inheriting the built-in default policy.
    #[serde(default)]
    pub(crate) domains: DomainRules,
    #[serde(default)]
    pub(crate) cidrs: CidrRules,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DomainRules {
    #[serde(default)]
    allow: Vec<Rule<DomainPattern>>,
    #[serde(default)]
    deny: Vec<Rule<DomainPattern>>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CidrRules {
    #[serde(default)]
    allow: Vec<Rule<IpNet>>,
    #[serde(default)]
    deny: Vec<Rule<IpNet>>,
    // on deserialization this defaults to false, while on Policy::default() this defaults to true
    #[serde(default)]
    deny_protected: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(
    untagged,
    deny_unknown_fields,
    bound(deserialize = "T: Deserialize<'de>")
)]
enum Rule<T> {
    Target(T),
    Detailed {
        target: T,
        #[serde(default)]
        ports: Option<Vec<u16>>,
    },
}

impl<T> Rule<T> {
    fn matches(&self, matches: &impl Fn(&T) -> bool, port: u16) -> bool {
        let (target, ports) = match self {
            Self::Target(target) => (target, None),
            Self::Detailed { target, ports } => (target, ports.as_deref()),
        };
        matches(target) && ports.is_none_or(|ports| ports.contains(&port))
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(try_from = "String")]
enum DomainPattern {
    Any,
    Exact(String),
    Subdomains(String),
}

impl TryFrom<String> for DomainPattern {
    type Error = String;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        if value == "*" {
            return Ok(Self::Any);
        }
        if let Some(suffix) = value.strip_prefix("*.") {
            return Ok(Self::Subdomains(Self::normalize(suffix)?));
        }
        Ok(Self::Exact(Self::normalize(&value)?))
    }
}

impl DomainPattern {
    fn normalize(domain: &str) -> Result<String, String> {
        let domain = domain.strip_suffix('.').unwrap_or(domain);
        if domain.is_empty() {
            return Err("domain is empty".into());
        }
        if !domain.is_ascii() {
            return Err("domain must use ASCII or its IDNA representation".into());
        }
        if domain.len() > 253 {
            return Err("domain exceeds 253 bytes".into());
        }

        for label in domain.split('.') {
            if label.is_empty() {
                return Err("domain contains an empty label".into());
            }
            if label.len() > 63 {
                return Err("domain label exceeds 63 bytes".into());
            }
            let bytes = label.as_bytes();
            if !bytes[0].is_ascii_alphanumeric() || !bytes[bytes.len() - 1].is_ascii_alphanumeric()
            {
                return Err("domain label must start and end with an ASCII letter or digit".into());
            }
            if !bytes
                .iter()
                .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-')
            {
                return Err("domain label contains an invalid character".into());
            }
        }

        Ok(domain.to_ascii_lowercase())
    }

    fn matches(&self, domain: &str) -> bool {
        match self {
            Self::Any => true,
            Self::Exact(expected) => domain == expected,
            Self::Subdomains(suffix) => {
                domain.len() > suffix.len()
                    && domain.ends_with(suffix)
                    && domain.as_bytes()[domain.len() - suffix.len() - 1] == b'.'
            }
        }
    }
}

impl DomainRules {
    pub(crate) fn allows(&self, domain: &str, port: u16) -> bool {
        let Ok(domain) = DomainPattern::normalize(domain) else {
            return false;
        };
        let matches = |pattern: &DomainPattern| pattern.matches(&domain);
        self.allow.iter().any(|rule| rule.matches(&matches, port))
            && !self.deny.iter().any(|rule| rule.matches(&matches, port))
    }
}

impl CidrRules {
    pub(crate) fn allows(&self, ip: IpAddr, port: u16) -> bool {
        let ip = ip.to_canonical();
        self.allow
            .iter()
            .any(|rule| rule.matches(&|network| network.contains(&ip), port))
            && !self.denies(ip, port)
    }

    pub(crate) fn denies(&self, ip: IpAddr, port: u16) -> bool {
        let ip = ip.to_canonical();
        self.deny
            .iter()
            .any(|rule| rule.matches(&|network| network.contains(&ip), port))
            || (self.deny_protected && Self::is_protected(ip))
    }

    fn is_protected(ip: IpAddr) -> bool {
        let standard = match ip {
            IpAddr::V4(ip) => {
                ip.is_unspecified()
                    || ip.is_loopback()
                    || ip.is_private()
                    || ip.is_link_local()
                    || ip.is_broadcast()
                    || ip.is_documentation()
                    || ip.is_multicast()
            }
            IpAddr::V6(ip) => {
                ip.is_unspecified()
                    || ip.is_loopback()
                    || ip.is_unique_local()
                    || ip.is_unicast_link_local()
                    || ip.is_multicast()
            }
        };
        standard
            || PROTECTED_CIDR_EXCEPTIONS
                .iter()
                .any(|network| network.contains(&ip))
    }
}

impl Default for Policy {
    // allow anything except protected.
    fn default() -> Self {
        Self {
            domains: DomainRules {
                allow: vec![Rule::Target(DomainPattern::Any)],
                deny: Vec::new(),
            },
            cidrs: CidrRules {
                allow: ["0.0.0.0/0", "::/0"]
                    .into_iter()
                    .map(|v| v.parse().unwrap())
                    .map(Rule::Target)
                    .collect(),
                deny: Vec::new(),
                deny_protected: true,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(source: &str) -> Policy {
        toml::from_str(source).unwrap()
    }

    fn ip(value: &str) -> IpAddr {
        value.parse().unwrap()
    }

    #[test]
    fn default_allows_public_and_denies_protected_destinations() {
        let policy = Policy::default();
        assert!(policy.domains.allows("example.com", 443));
        assert!(policy.cidrs.allows(ip("8.8.8.8"), 443));
        assert!(!policy.cidrs.allows(ip("10.0.0.1"), 443));
        assert!(!policy.cidrs.allows(ip("100.64.0.1"), 443));
        assert!(!policy.cidrs.allows(ip("127.0.0.1"), 443));
        assert!(!policy.cidrs.allows(ip("169.254.169.254"), 443));
        assert!(!policy.cidrs.allows(ip("fc00::1"), 443));
        assert!(!policy.cidrs.allows(ip("::ffff:127.0.0.1"), 443));
    }

    #[test]
    fn empty_user_policy_denies_everything() {
        let policy = policy("");
        assert!(!policy.domains.allows("example.com", 443));
        assert!(!policy.cidrs.allows(ip("8.8.8.8"), 443));
    }

    #[test]
    fn user_policy_can_deny_protected_destinations() {
        let unprotected = policy("[cidrs]\nallow = ['0.0.0.0/0', '::/0']");
        assert!(unprotected.cidrs.allows(ip("127.0.0.1"), 443));
        assert!(unprotected.cidrs.allows(ip("100.64.0.1"), 443));

        let protected = policy("[cidrs]\ndeny_protected = true\nallow = ['0.0.0.0/0', '::/0']");
        assert!(!protected.cidrs.allows(ip("127.0.0.1"), 443));
        assert!(!protected.cidrs.allows(ip("100.64.0.1"), 443));
    }

    #[test]
    fn allow_requires_a_match_and_deny_overrides_it() {
        let policy = policy(
            r#"
            [domains]
            allow = [{ target = "*.example.com", ports = [443] }]
            deny = [{ target = "blocked.example.com", ports = [443] }]

            [cidrs]
            allow = [{ target = "10.0.0.0/8", ports = [443] }]
            deny = [{ target = "10.1.0.0/16", ports = [443] }]
            "#,
        );

        assert!(policy.domains.allows("api.example.com", 443));
        assert!(!policy.domains.allows("api.example.com", 80));
        assert!(!policy.domains.allows("example.com", 443));
        assert!(!policy.domains.allows("blocked.example.com", 443));
        assert!(!policy.domains.allows("notexample.com", 443));
        assert!(policy.cidrs.allows(ip("10.2.0.1"), 443));
        assert!(!policy.cidrs.allows(ip("10.2.0.1"), 80));
        assert!(!policy.cidrs.allows(ip("10.1.0.1"), 443));
        assert!(!policy.cidrs.allows(ip("192.0.2.1"), 443));
    }

    #[test]
    fn resolved_ips_ignore_cidr_allow_and_honor_port_denies() {
        let policy = policy(
            r#"
            [domains]
            allow = [{ target = "example.com", ports = [443] }]

            [cidrs]
            deny = [{ target = "10.0.0.0/8", ports = [80] }]
            "#,
        );

        assert!(policy.domains.allows("example.com", 443));
        assert!(!policy.domains.allows("example.com", 80));
        assert!(!policy.cidrs.denies(ip("10.0.0.1"), 443));
        assert!(policy.cidrs.denies(ip("10.0.0.1"), 80));
        assert!(!policy.cidrs.allows(ip("10.0.0.1"), 443));
    }

    #[test]
    fn domain_matching_is_normalized() {
        let policy = policy(
            r#"
            [domains]
            allow = ["Example.COM", { target = "*.service.example", ports = [443] }]
            "#,
        );

        assert!(policy.domains.allows("EXAMPLE.com.", 80));
        assert!(policy.domains.allows("a.b.SERVICE.example", 443));
        assert!(!policy.domains.allows("a.b.SERVICE.example", 80));
        assert!(!policy.domains.allows("service.example", 443));
    }

    #[test]
    fn malformed_rules_and_unknown_fields_are_rejected() {
        assert!(toml::from_str::<Policy>("[domains]\nallow = ['foo*bar']").is_err());
        assert!(toml::from_str::<Policy>("unknown = true").is_err());
        assert!(
            toml::from_str::<Policy>(
                "[domains]\nallow = [{ target = 'example.com', unknown = true }]"
            )
            .is_err()
        );
    }
}
