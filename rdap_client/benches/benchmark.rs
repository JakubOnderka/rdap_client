use criterion::{black_box, criterion_group, criterion_main, Criterion};
use std::convert::TryFrom;
use std::fs::File;

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

    c.bench_function("serialize_bootstrap_dns", |b| {
        let mut dns = rdap_client::bootstrap::Dns::new();
        dns.insert(
            vec!["https://rdap-server1.example".into()],
            vec!["cz".into(), "sk".into(), "br".into(), "kr".into()],
        );
        dns.insert(
            vec!["https://rdap-server2.example".into()],
            vec!["fr".into(), "ak".into(), "rt".into(), "ayay".into()],
        );
        dns.insert(
            vec!["https://rdap-server3.example".into()],
            vec![
                "ee".into(),
                "xn--ngbrx".into(),
                "allstate".into(),
                "boehringer".into(),
            ],
        );
        b.iter(|| {
            serde_json::to_string(&dns).unwrap();
        });
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
