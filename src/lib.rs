//! Async and fast RDAP client and parser.

#![warn(rust_2018_idioms)]

use bootstrap::{Asn, Dns, Ip, ObjectTags};
use ip_network::IpNetwork;
use reqwest::header;
use reqwest::IntoUrl;
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::convert::TryFrom;
use std::net::IpAddr;
use std::time::Duration;

pub mod bootstrap;
pub mod parser;

/// Query value for search domain request.
pub enum SearchDomain {
    Name(String),
    NsLdhName(String),
    NsIp(IpAddr),
}

impl SearchDomain {
    fn key(&self) -> &'static str {
        match self {
            Self::Name(..) => "name",
            Self::NsLdhName(..) => "nsLdhName",
            Self::NsIp(..) => "nsIp",
        }
    }

    fn value(self) -> String {
        match self {
            Self::Name(value) => value,
            Self::NsLdhName(value) => value,
            Self::NsIp(value) => value.to_string(),
        }
    }
}

/// Query value for search entity request.
pub enum SearchEntity {
    Fn(String),
    Handle(String),
}

impl SearchEntity {
    fn key(&self) -> &'static str {
        match self {
            Self::Fn(..) => "fn",
            Self::Handle(..) => "handle",
        }
    }

    fn value(self) -> String {
        match self {
            Self::Fn(value) => value,
            Self::Handle(value) => value,
        }
    }
}

/// Query value for search nameserver request.
pub enum SearchNameserver {
    Name(String),
    Ip(IpAddr),
}

impl SearchNameserver {
    fn key(&self) -> &'static str {
        match self {
            Self::Name(..) => "name",
            Self::Ip(..) => "ip",
        }
    }

    fn value(self) -> String {
        match self {
            Self::Name(value) => value,
            Self::Ip(value) => value.to_string(),
        }
    }
}

/// Error enum returned by Client requests.
#[derive(Debug)]
pub enum ClientError {
    Reqwest(reqwest::Error),
    Server(reqwest::Response),
    Rdap(reqwest::Url, parser::Error),
}

const RDAP_CONTENT_TYPES: [&str; 2] = ["application/rdap+json", "application/json"];

fn is_rdap_response(response: &reqwest::Response) -> bool {
    if let Some(content_length) = response.content_length() {
        if content_length == 0 {
            return false;
        }
    }

    if let Some(content_type) = response.headers().get(header::CONTENT_TYPE) {
        if let Ok(content_type_str) = content_type.to_str() {
            return RDAP_CONTENT_TYPES
                .iter()
                .any(|rdap_type| content_type_str.contains(rdap_type));
        }
    }

    false
}

/// RDAP client.
#[derive(Default)]
pub struct Client {
    client: reqwest::Client,
}

impl Client {
    /// Creates new `Client` with with default configuration.
    pub fn new() -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .unwrap();

        Self::with_reqwest_client(client)
    }

    /// Creates new `Client` with given [reqwest](https://docs.rs/reqwest/) client.
    pub fn with_reqwest_client(client: reqwest::Client) -> Self {
        Self { client }
    }

    async fn get_boostrap<T: DeserializeOwned>(
        &self,
        url: &str,
    ) -> Result<parser::Bootstrap<T>, reqwest::Error> {
        self.client.get(url).send().await?.json().await
    }

    /// Fetch boostrap from IANA for ASN, IPv4 and IPV6, domains (DNS) and object tags.
    pub async fn fetch_bootstrap(
        &self,
    ) -> Result<bootstrap::Bootstrap, Box<dyn std::error::Error>> {
        let (parsed_asn, parsed_dns, parsed_ipv4, parsed_ipv6, parsed_object_tags) = futures::join!(
            self.get_boostrap("https://data.iana.org/rdap/asn.json"),
            self.get_boostrap("https://data.iana.org/rdap/dns.json"),
            self.get_boostrap("https://data.iana.org/rdap/ipv4.json"),
            self.get_boostrap("https://data.iana.org/rdap/ipv6.json"),
            self.get_boostrap("https://data.iana.org/rdap/object-tags.json"),
        );

        let asn = Asn::try_from(&parsed_asn?)?;
        let dns = Dns::from(&parsed_dns?);
        let ip = Ip::try_from((&parsed_ipv4?, &parsed_ipv6?))?;
        let object_tags = ObjectTags::try_from(&parsed_object_tags?)?;

        Ok(bootstrap::Bootstrap {
            ip,
            dns,
            asn,
            object_tags,
        })
    }

    async fn handle_response<T: DeserializeOwned>(
        response: reqwest::Response,
    ) -> Result<T, ClientError> {
        if response.status() == reqwest::StatusCode::OK {
            response.json::<T>().await.map_err(ClientError::Reqwest)
        } else if is_rdap_response(&response) {
            Err(ClientError::Rdap(
                response.url().clone(),
                response
                    .json::<parser::Error>()
                    .await
                    .map_err(ClientError::Reqwest)?,
            ))
        } else {
            Err(ClientError::Server(response))
        }
    }

    fn construct_headers() -> header::HeaderMap {
        let mut headers = header::HeaderMap::new();
        headers.insert(
            header::ACCEPT,
            header::HeaderValue::from_str(&RDAP_CONTENT_TYPES.join(", ")).unwrap(),
        );
        headers
    }

    async fn get<T: DeserializeOwned, I: IntoUrl>(&self, url: I) -> Result<T, ClientError> {
        self.client
            .get(url)
            .headers(Self::construct_headers())
            .send()
            .await
            .map(Self::handle_response)
            .map_err(ClientError::Reqwest)?
            .await
    }

    async fn get_with_query<T: DeserializeOwned, I: IntoUrl, Q: Serialize>(
        &self,
        url: I,
        query: &Q,
    ) -> Result<T, ClientError> {
        self.client
            .get(url)
            .query(query)
            .headers(Self::construct_headers())
            .send()
            .await
            .map(Self::handle_response)
            .map_err(ClientError::Reqwest)?
            .await
    }

    /// Query given RDAP server for IPv4 or IPv6 address.
    pub async fn query_ip<I: Into<IpAddr>>(
        &self,
        server: &str,
        ip: I,
    ) -> Result<parser::IpNetwork, ClientError> {
        let url = format!("{}ip/{}", server, ip.into());
        self.get(&url).await
    }

    /// Query given RDAP server for IP network.
    pub async fn query_ip_network<I: Into<IpNetwork>>(
        &self,
        server: &str,
        ip_network: I,
    ) -> Result<parser::IpNetwork, ClientError> {
        let ip_network = ip_network.into();
        let url = format!(
            "{}ip/{}/{}",
            server,
            ip_network.network_address(),
            ip_network.netmask()
        );
        self.get(&url).await
    }

    /// Query given RDAP server for AS number.
    pub async fn query_asn(&self, server: &str, asn: u32) -> Result<parser::AutNum, ClientError> {
        let url = format!("{}autnum/{}", server, asn);
        self.get(&url).await
    }

    /// Query given RDAP server for nameserver handle.
    pub async fn query_nameserver(
        &self,
        server: &str,
        nameserver: &str,
    ) -> Result<parser::Nameserver, ClientError> {
        let url = format!("{}nameserver/{}", server, nameserver);
        self.get(&url).await
    }

    /// Query given RDAP server for domain by name.
    pub async fn query_domain(
        &self,
        server: &str,
        domain: &str,
    ) -> Result<parser::Domain, ClientError> {
        let url = format!("{}domain/{}", server, domain);
        self.get(&url).await
    }

    pub async fn query_reverse_domain<I: Into<IpAddr>>(
        &self,
        server: &str,
        ip: I,
    ) -> Result<parser::Domain, ClientError> {
        let domain = match ip.into() {
            IpAddr::V4(ipv4) => {
                let octets = ipv4.octets();
                format!(
                    "{}.{}.{}.{}.in-addr.arpa",
                    octets[3], octets[2], octets[1], octets[0]
                )
            }
            IpAddr::V6(ipv6) => {
                let mut ret: [u8; 32] = Default::default();
                for (i, byte) in ipv6.octets().iter().enumerate() {
                    ret[i * 2] = byte >> 4;
                    ret[i * 2 + 1] = byte & 0xf;
                }
                ret.reverse();

                format!(
                    "{}.ip6.arpa",
                    ret.iter()
                        .map(|n| n.to_string())
                        .collect::<Vec<_>>()
                        .join(&".")
                )
            }
        };
        self.query_domain(server, &domain).await
    }

    /// Query given RDAP server for entity by its name.
    pub async fn query_entity(
        &self,
        server: &str,
        entity: &str,
    ) -> Result<parser::Entity, ClientError> {
        let url = format!("{}entity/{}", server, entity);
        self.get(&url).await
    }

    /// Search given RDAP server for nameserver by name or IP address.
    pub async fn search_nameserver(
        &self,
        server: &str,
        search_nameserver: SearchNameserver,
    ) -> Result<parser::NameserverSearchResults, ClientError> {
        let url = &format!("{}nameservers", server);
        self.get_with_query(
            url,
            &[(search_nameserver.key(), search_nameserver.value())],
        )
        .await
    }

    /// Search given RDAP server for domain by name, NS LDH name or NS IP address.
    pub async fn search_domain(
        &self,
        server: &str,
        search_domain: SearchDomain,
    ) -> Result<parser::DomainSearchResults, ClientError> {
        let url = format!("{}domains", server);
        self.get_with_query(
            &url,
            &[(search_domain.key(), search_domain.value())],
        )
        .await
    }

    /// Search given RDAP server for domain by FN or handle.
    pub async fn search_entity(
        &self,
        server: &str,
        search_entity: SearchEntity,
    ) -> Result<parser::EntitySearchResults, ClientError> {
        let url = format!("{}entities", server);
        self.get_with_query(
            &url,
            &[(search_entity.key(), search_entity.value())],
        )
        .await
    }

    /// Method from [`arin_originas0` extension.](https://bitbucket.org/arin-specs/arin-rdap-originas/src/master/arin-rdap-originas.txt).
    /// Given server must support this method. Returns result of `IpNetwork`s.
    pub async fn search_networks_by_origin_as(
        &self,
        server: &str,
        asn: u32,
    ) -> Result<parser::ArinOriginas0OriginautnumsResults, ClientError> {
        let url = format!(
            "{}arin_originas0_networksbyoriginas/{}",
            server, asn
        );
        self.get(&url).await
    }

    /// Help method.
    pub async fn help(&self, server: &str) -> Result<parser::Help, ClientError> {
        let url = format!("{}help/", server);
        self.get(&url).await
    }
}
