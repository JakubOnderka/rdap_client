use criterion::{black_box, criterion_group, criterion_main, Criterion};
use std::convert::TryFrom;
use std::fs::File;
use std::io::Read;
use std::str::FromStr;

fn criterion_benchmark(c: &mut Criterion) {
    c.bench_function("bootstrap_asn_find", |b| {
        let file = File::open("test_data/bootstrap/asn.json").unwrap();
        let parsed = serde_json::from_reader(file).unwrap();
        let asn = rdap_client::bootstrap::Asn::try_from(&parsed).unwrap();

        b.iter(|| asn.find(black_box(37838)).unwrap()[0].as_str())
    });

    c.bench_function("bootstrap_dns_find", |b| {
        let file = File::open("test_data/bootstrap/dns.json").unwrap();
        let parsed = serde_json::from_reader(file).unwrap();
        let dns = rdap_client::bootstrap::Dns::try_from(&parsed).unwrap();

        b.iter(|| dns.find(black_box("cz")).unwrap()[0].as_str())
    });

    c.bench_function("parse", |b| {
        let mut file = File::open("test_data/ip_network/ip_network_26.json").unwrap();
        let mut json = String::new();
        file.read_to_string(&mut json).unwrap();

        b.iter(|| {
            serde_json::from_str::<rdap_client::parser::IpNetwork>(&json).unwrap();
        });
    });

    c.bench_function("deserialize_enum", |b| {
        let json = r#""last changed""#;

        b.iter(|| {
            serde_json::from_str::<rdap_client::parser::EventAction>(&json).unwrap();
        });
    });

    c.bench_function("deserialize_jcard", |b| {
        let json = r#"["vcard",[["version",{},"text","4.0"],["fn",{},"text",""],["adr",{"cc":"US","iso-3166-1-alpha-2":"US"},"text","","","","","Washington","",""],["org",{},"text","Amazon Registry Services, Inc."]]]"#;

        b.iter(|| {
            serde_json::from_str::<rdap_client::parser::JCard>(&json).unwrap();
        });
    });

    c.bench_function("countrycode_display", |b| {
        let country_code = rdap_client::parser::CountryCode::from_str("CZ").unwrap();
        b.iter(|| {
            serde_json::to_string(&country_code).unwrap();
        });
    });

    c.bench_function("serialize_bootstrap_dns", |b| {
       let mut dns = rdap_client::bootstrap::Dns::new();
        dns.insert(vec!["https://rdap-server1.example".into()], vec!["cz".into(), "sk".into(), "br".into(), "kr".into()]);
        dns.insert(vec!["https://rdap-server2.example".into()], vec!["fr".into(), "ak".into(), "rt".into(), "ayay".into()]);
        dns.insert(vec!["https://rdap-server3.example".into()], vec!["ee".into(), "xn--ngbrx".into(), "allstate".into(), "boehringer".into()]);
        b.iter(|| {
            serde_json::to_string(&dns).unwrap();
        });
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
