use crate::parser::{self, BootstrapService};
use ip_network::{IpNetwork, IpNetworkParseError};
use ip_network_table::IpNetworkTable;
use serde::de::{SeqAccess, Visitor};
use serde::ser::SerializeSeq;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::collections::HashMap;
use std::convert::TryFrom;
use std::fmt;
use std::net::IpAddr;
use std::ops::RangeInclusive;
use std::str::FromStr;
use std::sync::Arc;

fn hashmap_serializer<'a, S: Serializer, V: Serialize>(
    serializer: S,
    input: impl Iterator<Item = (V, &'a Arc<Vec<String>>)>,
) -> Result<S::Ok, S::Error> {
    let mut hashmap: HashMap<Arc<Vec<String>>, Vec<V>> = HashMap::new();
    for (value, servers) in input {
        if let Some(k) = hashmap.get_mut(servers) {
            k.push(value);
        } else {
            hashmap.insert(Arc::clone(servers), vec![value]);
        }
    }

    let mut seq = serializer.serialize_seq(Some(hashmap.len()))?;
    for (k, v) in hashmap {
        seq.serialize_element(&(v, k.as_ref()))?;
    }
    seq.end()
}

#[derive(Serialize, Deserialize)]
pub struct Bootstrap {
    pub dns: Dns,
    pub ip: Ip,
    pub asn: Asn,
    pub object_tags: ObjectTags,
}

#[derive(Debug, Default)]
struct ArcHashMap(HashMap<String, Arc<Vec<String>>>);

impl ArcHashMap {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn with_capacity(capacity: usize) -> Self {
        Self(HashMap::with_capacity(capacity))
    }

    pub fn insert(&mut self, servers: Vec<String>, keys: Vec<String>) {
        let servers = Arc::new(servers);
        for key in keys {
            self.0.insert(key, Arc::clone(&servers));
        }
    }

    pub fn get(&self, key: &str) -> Option<&Vec<String>> {
        self.0.get(key).map(|i| i.as_ref())
    }

    pub fn iter(&self) -> impl Iterator<Item = (&String, &Vec<String>)> {
        self.0.iter().map(|(k, v)| (k, v.as_ref()))
    }
}

impl<I: BootstrapService> From<&parser::Bootstrap<I>> for ArcHashMap {
    fn from(bootstrap: &parser::Bootstrap<I>) -> Self {
        let mut hashmap = Self::new();
        for service in &bootstrap.services {
            hashmap.insert(service.servers().to_vec(), service.keys().to_vec());
        }
        hashmap
    }
}

impl Serialize for ArcHashMap {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        hashmap_serializer(serializer, self.0.iter())
    }
}

impl<'de> Deserialize<'de> for ArcHashMap {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct ArcHashMapVisitor;

        impl<'de> Visitor<'de> for ArcHashMapVisitor {
            type Value = ArcHashMap;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a sequence")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut hashmap = ArcHashMap::with_capacity(seq.size_hint().unwrap_or(0));
                while let Some((keys, servers)) =
                    seq.next_element::<(Vec<String>, Vec<String>)>()?
                {
                    hashmap.insert(servers, keys);
                }
                Ok(hashmap)
            }
        }

        deserializer.deserialize_seq(ArcHashMapVisitor)
    }
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct Dns(ArcHashMap);

impl Dns {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn insert(&mut self, servers: Vec<String>, domains: Vec<String>) {
        self.0.insert(servers, domains);
    }

    pub fn find(&self, domain: &str) -> Option<&Vec<String>> {
        let domain_parts: Vec<_> = domain.split('.').collect();
        for i in 0..domain_parts.len() {
            let domain_to_check = domain_parts[i..].join(".");
            if let Some(servers) = self.0.get(&domain_to_check) {
                return Some(servers);
            }
        }

        None
    }

    pub fn iter(&self) -> impl Iterator<Item = (&String, &Vec<String>)> {
        self.0.iter()
    }
}

impl From<&parser::BootstrapRfc7484> for Dns {
    fn from(bootstrap: &parser::BootstrapRfc7484) -> Self {
        Self(ArcHashMap::from(bootstrap))
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ObjectTags(ArcHashMap);

impl ObjectTags {
    pub fn find(&self, name: &str) -> Option<&Vec<String>> {
        let handle_last_part = name.split('-').last().unwrap();
        self.0.get(handle_last_part)
    }

    pub fn iter(&self) -> impl Iterator<Item = (&String, &Vec<String>)> {
        self.0.iter()
    }
}

impl From<&parser::BootstrapRfc8521> for ObjectTags {
    fn from(bootstrap: &parser::BootstrapRfc8521) -> Self {
        Self(ArcHashMap::from(bootstrap))
    }
}

pub struct Ip(IpNetworkTable<Arc<Vec<String>>>);

impl Ip {
    pub fn find<I: Into<IpAddr>>(&self, ip: I) -> Option<&Vec<String>> {
        self.0.longest_match(ip.into()).map(|(_, v)| v.as_ref())
    }

    pub fn iter(&self) -> impl Iterator<Item = (IpNetwork, &Vec<String>)> {
        self.0.iter().map(|(i, v)| (i, v.as_ref()))
    }
}

impl Serialize for Ip {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        hashmap_serializer(serializer, self.0.iter())
    }
}

impl<'de> Deserialize<'de> for Ip {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct IpVisitor;

        impl<'de> Visitor<'de> for IpVisitor {
            type Value = Ip;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a sequence")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut ip_table = IpNetworkTable::new();
                while let Some((networks, servers)) =
                    seq.next_element::<(Vec<IpNetwork>, Vec<String>)>()?
                {
                    let servers = Arc::new(servers);
                    for network in networks {
                        ip_table.insert(network, Arc::clone(&servers));
                    }
                }
                Ok(Ip(ip_table))
            }
        }

        deserializer.deserialize_seq(IpVisitor)
    }
}

impl TryFrom<(&parser::BootstrapRfc7484, &parser::BootstrapRfc7484)> for Ip {
    type Error = IpNetworkParseError;

    fn try_from(
        bootstraps: (&parser::BootstrapRfc7484, &parser::BootstrapRfc7484),
    ) -> Result<Self, Self::Error> {
        let mut table = IpNetworkTable::new();

        for bootstrap in &[bootstraps.0, bootstraps.1] {
            for service in &bootstrap.services {
                let servers = Arc::new(service.servers().to_vec());
                for key in service.keys() {
                    table.insert(IpNetwork::from_str(key)?, Arc::clone(&servers));
                }
            }
        }

        Ok(Self(table))
    }
}

#[derive(Default)]
pub struct Asn(Vec<(RangeInclusive<u32>, Arc<Vec<String>>)>);

impl Asn {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn with_capacity(capacity: usize) -> Self {
        Asn(Vec::with_capacity(capacity))
    }

    pub fn find(&self, asn: u32) -> Option<&Vec<String>> {
        let pos = self
            .0
            .binary_search_by_key(&asn, |(range, _)| *range.start())
            .unwrap_or_else(|e| e.saturating_sub(1));
        let (range, servers) = &self.0[pos];
        if range.contains(&asn) {
            Some(servers.as_ref())
        } else {
            None
        }
    }

    pub fn insert(&mut self, servers: Vec<String>, ranges: Vec<RangeInclusive<u32>>) {
        let servers = Arc::new(servers);
        for range in ranges {
            self.insert_one(range, &servers);
        }
    }

    pub fn insert_one(&mut self, range: RangeInclusive<u32>, servers: &Arc<Vec<String>>) {
        self.0.push((range, Arc::clone(&servers)));
    }

    pub fn sort(&mut self) {
        self.0.sort_by_key(|(a, _)| *a.start());
    }

    pub fn iter(&self) -> impl Iterator<Item = (&RangeInclusive<u32>, &Vec<String>)> {
        self.0.iter().map(|(i, v)| (i, v.as_ref()))
    }
}

impl Serialize for Asn {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let i = self.0.iter().map(|(range, arc)| {
            let range = (*range.start(), *range.end());
            (range, arc)
        });
        hashmap_serializer(serializer, i)
    }
}

impl<'de> Deserialize<'de> for Asn {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct AsnVisitor;

        type InnerType = (Vec<(u32, u32)>, Vec<String>);

        impl<'de> Visitor<'de> for AsnVisitor {
            type Value = Asn;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a sequence")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut asn = Asn::with_capacity(seq.size_hint().unwrap_or(0));

                while let Some((ranges, servers)) = seq.next_element::<InnerType>()? {
                    let ranges = ranges
                        .iter()
                        .map(|(start, stop)| RangeInclusive::new(*start, *stop))
                        .collect();

                    asn.insert(servers, ranges);
                }

                asn.sort();
                Ok(asn)
            }
        }

        deserializer.deserialize_seq(AsnVisitor)
    }
}

impl TryFrom<&parser::BootstrapRfc7484> for Asn {
    type Error = std::num::ParseIntError;

    fn try_from(bootstrap: &parser::BootstrapRfc7484) -> Result<Self, Self::Error> {
        let mut asn = Asn::new();

        for service in &bootstrap.services {
            let servers = Arc::new(service.servers().to_vec());
            for key in service.keys() {
                let range = if key.contains('-') {
                    let parts: Vec<_> = key.splitn(2, '-').collect();
                    RangeInclusive::new(
                        parts.get(0).unwrap_or(&"").parse::<u32>()?,
                        parts.get(1).unwrap_or(&"").parse::<u32>()?,
                    )
                } else {
                    let asn = key.parse::<u32>()?;
                    RangeInclusive::new(asn, asn)
                };
                asn.insert_one(range, &servers);
            }
        }

        asn.sort();

        Ok(asn)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::de::DeserializeOwned;
    use std::fs::File;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn parse<T: DeserializeOwned>(path: &str) -> T {
        let file = File::open(format!("test_data/bootstrap/{}", path)).unwrap();
        let parsed: T = serde_json::from_reader(file).unwrap();
        parsed
    }

    #[test]
    fn test_asn() {
        let parsed = parse("asn.json");
        let asn = Asn::try_from(&parsed).unwrap();
        assert!(asn.find(std::u32::MAX).is_none());
        assert!(asn.find(0).is_none());
        assert_eq!("https://rdap.apnic.net/", asn.find(4608).unwrap()[0]);
        assert_eq!("https://rdap.db.ripe.net/", asn.find(2043).unwrap()[0]);
        assert_eq!(
            "https://rdap.lacnic.net/rdap/",
            asn.find(267676).unwrap()[0]
        );

        let ser_json = serde_json::to_string(&asn).unwrap();
        let asn_de: Asn = serde_json::from_str(&ser_json).unwrap();
        assert_eq!("https://rdap.apnic.net/", asn_de.find(4608).unwrap()[0]);
        assert_eq!("https://rdap.db.ripe.net/", asn_de.find(2043).unwrap()[0]);
    }

    #[test]
    fn test_dns() {
        let parsed = parse("dns.json");
        let dns = Dns::from(&parsed);
        assert_eq!("https://rdap.nic.cz/", dns.find("a.nic.cz").unwrap()[0]);
        assert_eq!(
            "https://rdap.verisign.com/com/v1/",
            dns.find("a.b.com").unwrap()[0]
        );
        assert!(dns.find("com.a.b.xxxxxxxxxxxxxx").is_none());

        let ser_json = serde_json::to_string(&dns).unwrap();
        let dns_de: Dns = serde_json::from_str(&ser_json).unwrap();
        assert_eq!("https://rdap.nic.cz/", dns_de.find("a.nic.cz").unwrap()[0]);
    }

    #[test]
    fn test_ip() {
        let ipv4_bootstrap = parse("ipv4.json");
        let ipv6_bootstrap = parse("ipv6.json");
        let ip = Ip::try_from((&ipv4_bootstrap, &ipv6_bootstrap)).unwrap();
        assert_eq!(
            "https://rdap.arin.net/registry/",
            ip.find(Ipv4Addr::new(8, 8, 8, 8)).unwrap()[0]
        );

        let ser_json = serde_json::to_string(&ip).unwrap();
        let ip_de: Ip = serde_json::from_str(&ser_json).unwrap();
        assert_eq!(
            "https://rdap.arin.net/registry/",
            ip_de.find(Ipv4Addr::new(8, 8, 8, 8)).unwrap()[0]
        );
    }

    #[test]
    fn test_object_tags() {
        let parsed = parse("object-tags.json");
        let object_tags = ObjectTags::from(&parsed);
        assert_eq!(
            "https://rdap.db.ripe.net/",
            object_tags.find("TEST-RIPE").unwrap()[0]
        );
        assert!(object_tags.find("TEST").is_none());
        assert!(object_tags.find("").is_none());
        assert!(object_tags.find("TEST-TEST").is_none());

        let ser_json = serde_json::to_string(&object_tags).unwrap();
        let object_tags_de: ObjectTags = serde_json::from_str(&ser_json).unwrap();
        assert_eq!(
            "https://rdap.db.ripe.net/",
            object_tags_de.find("TEST-RIPE").unwrap()[0]
        );
    }

    fn validate_bootstrap(bootstrap: &Bootstrap) {
        assert_eq!(
            "https://rdap.nic.cz/",
            bootstrap.dns.find("a.nic.cz").unwrap()[0]
        );
        assert!(bootstrap.dns.find("NOT-EXISTS").is_none());
        assert_eq!(
            "https://rdap.db.ripe.net/",
            bootstrap.object_tags.find("TEST-RIPE").unwrap()[0]
        );
        assert!(bootstrap.object_tags.find("NOT-EXISTS").is_none());
        assert_eq!(
            "https://rdap.arin.net/registry/",
            bootstrap.ip.find(Ipv4Addr::new(8, 8, 8, 8)).unwrap()[0]
        );
        assert!(bootstrap
            .ip
            .find(Ipv4Addr::new(255, 255, 255, 255))
            .is_none());
        assert_eq!(
            "https://rdap.arin.net/registry/",
            bootstrap
                .ip
                .find(Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888))
                .unwrap()[0]
        );
        assert_eq!(
            "https://rdap.apnic.net/",
            bootstrap.asn.find(4608).unwrap()[0]
        );
        assert!(bootstrap.asn.find(0).is_none());
    }

    #[test]
    fn test_bootstrap() {
        let parsed = parse("asn.json");
        let asn = Asn::try_from(&parsed).unwrap();

        let parsed = parse("dns.json");
        let dns = Dns::from(&parsed);

        let ipv4_bootstrap = parse("ipv4.json");
        let ipv6_bootstrap = parse("ipv6.json");
        let ip = Ip::try_from((&ipv4_bootstrap, &ipv6_bootstrap)).unwrap();

        let parsed = parse("object-tags.json");
        let object_tags = ObjectTags::from(&parsed);

        let bootstrap = Bootstrap {
            asn,
            dns,
            ip,
            object_tags,
        };

        validate_bootstrap(&bootstrap);

        let ser_json = serde_json::to_string(&bootstrap).unwrap();
        let bootstrap_de = serde_json::from_str(&ser_json).unwrap();

        validate_bootstrap(&bootstrap_de);
    }

    #[test]
    fn test_send_sync() {
        fn is_send_sync<T: Send + Sync>() {}
        is_send_sync::<Bootstrap>(); // compiles only if true
    }
}
