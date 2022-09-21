use criterion::{criterion_group, criterion_main, Criterion};
use std::fs::File;
use std::io::Read;
use std::str::FromStr;

fn criterion_benchmark(c: &mut Criterion) {
    c.bench_function("parse", |b| {
        let mut file = File::open("test_data/ip_network/ip_network_26.json").unwrap();
        let mut json = String::new();
        file.read_to_string(&mut json).unwrap();

        b.iter(|| {
            serde_json::from_str::<rdap_types::IpNetwork>(&json).unwrap();
        });
    });

    c.bench_function("deserialize_enum", |b| {
        let json = r#""last changed""#;

        b.iter(|| {
            serde_json::from_str::<rdap_types::EventAction>(&json).unwrap();
        });
    });

    c.bench_function("deserialize_jcard", |b| {
        let json = r#"["vcard",[["version",{},"text","4.0"],["fn",{},"text",""],["adr",{"cc":"US","iso-3166-1-alpha-2":"US"},"text","","","","","Washington","",""],["org",{},"text","Amazon Registry Services, Inc."]]]"#;

        b.iter(|| {
            serde_json::from_str::<rdap_types::JCard>(&json).unwrap();
        });
    });

    c.bench_function("countrycode_display", |b| {
        let country_code = rdap_types::CountryCode::from_str("CZ").unwrap();
        b.iter(|| {
            serde_json::to_string(&country_code).unwrap();
        });
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
