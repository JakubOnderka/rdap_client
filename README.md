rdap_client
========

Async and fast RDAP client and parser for Rust.

[![Documentation](https://docs.rs/rdap_client/badge.svg)](https://docs.rs/rdap_client)
[![Build Status](https://travis-ci.com/JakubOnderka/rdap_client.svg?branch=master)](https://travis-ci.com/JakubOnderka/rdap_client)
[![Crates.io](https://img.shields.io/crates/v/rdap_client.svg)](https://crates.io/crates/rdap_client)

## Usage

Add this to your `Cargo.toml`:

```toml
[dependencies]
rdap_client = "0.2"
tokio = "0.2"
```

and then you can use it like this:

```rust
use rdap_client::Client;

#[tokio::main]
async fn main() {
    let client = Client::new();
    let domain_to_check = "nic.cz";
    // Fetch boostrap from IANA.
    let bootstrap = client.fetch_bootstrap().await.unwrap();
    // Find what RDAP server to use for given domain.
    if let Some(servers) = bootstrap.dns.find(&domain_to_check) {
        let response = client.query_domain(&servers[0], domain_to_check).await.unwrap();
        println!("{}", response.handle);
    }
}
```

## Supported standards

* [RFC 7480: HTTP Usage in the Registration Data Access Protocol (RDAP)](https://tools.ietf.org/html/rfc7480)
* [RFC 7482: Registration Data Access Protocol (RDAP) Query Format](https://tools.ietf.org/html/rfc7482)
* [RFC 7483: JSON Responses for the Registration Data Access Protocol (RDAP)](https://tools.ietf.org/html/rfc7483)
* [RFC 8056: Extensible Provisioning Protocol (EPP) and Registration Data Access Protocol (RDAP) Status Mapping](https://tools.ietf.org/html/rfc8056)
* [RFC 8521: Registration Data Access Protocol (RDAP) Object Tagging](https://tools.ietf.org/html/rfc8521)
* [RDAP JSON Values](https://www.iana.org/assignments/rdap-json-values/rdap-json-values.xhtml)

## Supported extensions

* [`fred`](https://fred.nic.cz/rdap-extension/)
* [`cidr0`](https://bitbucket.org/nroecg/nro-rdap-cidr/src/master/nro-rdap-cidr.txt)
* [`arin_originas0`](https://bitbucket.org/arin-specs/arin-rdap-originas/src/master/arin-rdap-originas.txt)
* [`rdap_objectTag`](https://www.iana.org/go/rfc8521) (RFC 8521)

## Non standard responses

Not all RDAP servers follows RFC 7483 and then parser cannot parse that responses correctly. If that happend, feel 
free to open issue with URI that `rdap_client` could not parse.

## Useful articles 

* [RIPE NCC RDAP Implementation](https://github.com/RIPE-NCC/whois/blob/master/README.RDAP.md)
* [ARIN RDAP manual](https://www.arin.net/resources/registry/whois/rdap/)
