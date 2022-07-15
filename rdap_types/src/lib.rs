use chrono::{DateTime, FixedOffset, Offset, TimeZone, Utc};
use serde::de::{IntoDeserializer, SeqAccess, Unexpected, Visitor};
use serde::ser::SerializeSeq;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_with::skip_serializing_none;
use std::convert::TryFrom;
use std::fmt;
use std::fmt::Write;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::slice::Iter;
use std::str::FromStr;

fn deserialize_string_lowercase<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let mut string = String::deserialize(deserializer)?;
    // Just convert in case that string contains uppercase character
    // This solution is about 70% faster than convert it in all cases
    if string.chars().any(|c| c.is_uppercase()) {
        string = string.to_lowercase();
    }
    Ok(string)
}

/// Because not all RDAP servers are RFC 7483 complaint (they use datetime in formats that are
/// incompatible with RFC 3339), this method can parse all kinds of different format used in domains
/// RDAP servers:
/// - RFC 3339 format
/// - %Y-%m-%dT%H:%M:%S
/// - %Y-%m-%dT%H:%M:%SZ%z
/// - %Y-%m-%d %H:%M:%S
fn deserialize_datetime<'de, D>(deserializer: D) -> Result<DateTime<FixedOffset>, D::Error>
where
    D: Deserializer<'de>,
{
    let string = String::deserialize(deserializer)?;

    DateTime::parse_from_rfc3339(&string)
        .or_else(|_| {
            if string.contains('T') {
                Utc.datetime_from_str(&string, "%Y-%m-%dT%H:%M:%S")
                    .map(|d| d.with_timezone(&Utc.fix()))
                    .or_else(|_| DateTime::parse_from_str(&string, "%Y-%m-%dT%H:%M:%SZ%z"))
            } else {
                Utc.datetime_from_str(&string, "%Y-%m-%d %H:%M:%S")
                    .map(|d| d.with_timezone(&Utc.fix())) // for `xn--rhqv96g` domain
            }
        })
        .map_err(serde::de::Error::custom)
}

/// Two letters (usually ISO 3166-1) country code.
// Some registries uses codes that are not ISO 3166-1 countries (for example RIPe uses 'EU'
// as country), so we store that string as two bytes and not as for example isocountry::CountryCode.
#[derive(PartialEq)]
pub struct CountryCode([u8; 2]);

impl FromStr for CountryCode {
    type Err = &'static str;

    fn from_str(string: &str) -> Result<Self, Self::Err> {
        let bytes = string.as_bytes();
        if !bytes.is_ascii() || bytes.len() != 2 {
            return Err("string is not two letter ascii");
        }
        Ok(Self([
            bytes[0].to_ascii_uppercase(),
            bytes[1].to_ascii_uppercase(),
        ]))
    }
}

impl fmt::Debug for CountryCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "{}", self)
    }
}

impl fmt::Display for CountryCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        f.write_char(self.0[0] as char)?;
        f.write_char(self.0[1] as char)
    }
}

impl Serialize for CountryCode {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let string = std::str::from_utf8(&self.0).unwrap(); // should never fail
        serializer.serialize_str(string)
    }
}

impl<'de> Deserialize<'de> for CountryCode {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct CountryCodeVisitor;

        impl<'de> Visitor<'de> for CountryCodeVisitor {
            type Value = CountryCode;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(formatter, "expecting a two letters country code")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                CountryCode::from_str(v).map_err(|_| {
                    serde::de::Error::invalid_value(serde::de::Unexpected::Str(v), &self)
                })
            }
        }

        deserializer.deserialize_str(CountryCodeVisitor)
    }
}

/// https://tools.ietf.org/html/rfc7483#section-4.2
#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug)]
pub struct Link {
    pub value: Option<String>,
    pub rel: Option<String>,
    pub href: String,
    pub hreflang: Option<Vec<String>>,
    pub title: Option<String>,
    pub media: Option<String>,
    #[serde(rename = "type")]
    pub typ: Option<String>,
}

/// Value signifying the relationship an object would have with its closest containing object.
/// Values come from [RFC 7483] and [RDAP JSON Values].
///
/// [RFC 7483]: https://tools.ietf.org/html/rfc7483#section-10.2.4
/// [RDAP JSON Values]: https://www.iana.org/assignments/rdap-json-values/rdap-json-values.xhtml
#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone, Copy)]
#[serde(rename_all = "lowercase")]
#[serde(remote = "Role")]
pub enum Role {
    /// The entity object instance is the registrant of the registration. In some registries, this is known as a maintainer.
    Registrant,
    /// The entity object instance is a technical contact for the registration.
    Technical,
    /// The entity object instance is an administrative contact for the registration.
    Administrative,
    /// The entity object instance handles network abuse issues on behalf of the registrant of the registration.
    Abuse,
    /// The entity object instance handles payment and billing issues on behalf of the registrant of the registration.
    Billing,
    /// The entity object instance represents the authority responsible for the registration in the registry.
    Registrar,
    /// The entity object instance represents a third party through which the registration was conducted (i.e., not the registry or registrar).
    Reseller,
    /// The entity object instance represents a domain policy sponsor, such as an ICANN-approved sponsor.
    Sponsor,
    /// The entity object instance represents a proxy for another entity object, such as a registrant.
    Proxy,
    /// An entity object instance designated to receive notifications about association object instances.
    Notifications,
    /// The entity object instance handles communications related to a network operations center (NOC).
    Noc,
    /// Non standard
    Routing,
    /// Non standard role used by ARIN registry.
    Dns,
    /// Non standard role used by RIPE NCC for reverse domain response. See [RIPE NCC RDAP Implementation](https://github.com/RIPE-NCC/whois/blob/master/README.RDAP.md#custom-zone-role-for-domain-objects).
    Zone,
}

impl<'de> Deserialize<'de> for Role {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = deserialize_string_lowercase(deserializer)?;

        // Non standard for 'tirol' domain - https://rdap.ryce-rsp.com/rdap/
        match s.as_str() {
            "tech" => Ok(Self::Technical),
            "admin" => Ok(Self::Administrative),
            _ => Self::deserialize(s.into_deserializer()),
        }
    }
}

impl Serialize for Role {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        Self::serialize(self, serializer)
    }
}

/// https://tools.ietf.org/html/rfc7483#section-4.8
#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug)]
pub struct PublicId {
    #[serde(rename = "type")]
    pub typ: String,
    pub identifier: String,
}

#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum JCardType {
    Vcard,
}

/// https://tools.ietf.org/html/rfc6350#section-4
#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq)]
#[serde(rename_all = "kebab-case")]
#[serde(remote = "JCardItemDataType")]
pub enum JCardItemDataType {
    Text,
    TextList,
    DateList,
    TimeList,
    DateTimeList,
    DateAndOrTimeList,
    TimestampList,
    Boolean,
    IntegerList,
    FloatList,
    Uri,
    UtcOffset,
    LanguageTag,
    IanaValuespec,
    /// See https://tools.ietf.org/html/rfc7095#section-5
    Unknown,
}

impl<'de> Deserialize<'de> for JCardItemDataType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = deserialize_string_lowercase(deserializer)?;
        Self::deserialize(s.into_deserializer())
    }
}

impl Serialize for JCardItemDataType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        Self::serialize(self, serializer)
    }
}

#[derive(Debug)]
pub struct JCardItem {
    pub property_name: String,
    pub parameters: serde_json::Map<String, serde_json::Value>,
    pub type_identifier: JCardItemDataType,
    pub values: Vec<serde_json::Value>,
}

impl<'de> Deserialize<'de> for JCardItem {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct JCardItemVisitor;

        impl<'de> Visitor<'de> for JCardItemVisitor {
            type Value = JCardItem;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a sequence")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let invalid_length =
                    |size| serde::de::Error::invalid_length(size, &"at least four elements");

                // Property name must be lowercase string, see https://tools.ietf.org/html/rfc7095#section-3.3
                let mut property_name: String =
                    seq.next_element()?.ok_or_else(|| invalid_length(0))?;
                if property_name.chars().any(|c| c.is_uppercase()) {
                    property_name = property_name.to_lowercase();
                }

                let parameters = seq.next_element()?.ok_or_else(|| invalid_length(1))?;
                let type_identifier = seq.next_element()?.ok_or_else(|| invalid_length(2))?;

                let mut values = vec![];
                while let Some(value) = seq.next_element()? {
                    values.push(value);
                }

                if values.is_empty() {
                    return Err(invalid_length(3));
                }

                Ok(JCardItem {
                    property_name,
                    parameters,
                    type_identifier,
                    values,
                })
            }
        }

        deserializer.deserialize_seq(JCardItemVisitor)
    }
}

impl Serialize for JCardItem {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut seq = serializer.serialize_seq(Some(3 + self.values.len()))?;
        seq.serialize_element(&self.property_name)?;
        seq.serialize_element(&self.parameters)?;
        seq.serialize_element(&self.type_identifier)?;
        for value in &self.values {
            seq.serialize_element(value)?;
        }
        seq.end()
    }
}

/// https://tools.ietf.org/html/rfc7095
#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug)]
pub struct JCard(JCardType, Vec<JCardItem>);

impl JCard {
    pub fn typ(&self) -> JCardType {
        self.0
    }

    pub fn items(&self) -> &Vec<JCardItem> {
        &self.1
    }

    /// name as lowercase string.
    pub fn items_by_name(&self, name: &str) -> Vec<&JCardItem> {
        self.1.iter().filter(|p| p.property_name == name).collect()
    }
}

#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Entity {
    pub handle: Option<String>,
    pub vcard_array: Option<JCard>,
    pub roles: Option<Vec<Role>>,
    pub public_ids: Option<Vec<PublicId>>,
    pub entities: Option<Vec<Entity>>,
    pub remarks: Option<NoticesOrRemarks>,
    pub links: Option<Vec<Link>>,
    pub events: Option<Events>,
    pub as_event_actor: Option<Events>,
    pub status: Option<Vec<Status>>,
    pub port43: Option<String>,
    pub lang: Option<String>,
    pub object_class_name: String,
}

/// https://tools.ietf.org/html/rfc7483#section-10.2.2
#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone, Copy)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    Validated,
    #[serde(rename = "renew prohibited")]
    RenewProhibited,
    #[serde(rename = "update prohibited")]
    UpdateProhibited,
    #[serde(rename = "transfer prohibited")]
    TransferProhibited,
    #[serde(rename = "delete prohibited")]
    DeleteProhibited,
    Proxy,
    Private,
    Removed,
    Obscured,
    Associated,
    Active,
    Inactive,
    Locked,
    #[serde(rename = "pending create")]
    PendingCreate,
    #[serde(rename = "pending renew")]
    PendingRenew,
    #[serde(rename = "pending transfer")]
    PendingTransfer,
    #[serde(rename = "pending update")]
    PendingUpdate,
    #[serde(rename = "pending delete")]
    PendingDelete,
    // From RFC8056
    #[serde(rename = "add period")]
    AddPeriod,
    #[serde(rename = "auto renew period")]
    AutoRenewPeriod,
    #[serde(rename = "client delete prohibited")]
    ClientDeleteProhibited,
    #[serde(rename = "client hold")]
    ClientHold,
    #[serde(rename = "client renew prohibited")]
    ClientRenewProhibited,
    #[serde(rename = "client transfer prohibited")]
    ClientTransferProhibited,
    #[serde(rename = "client update prohibited")]
    ClientUpdateProhibited,
    #[serde(rename = "pending restore")]
    PendingRestore,
    #[serde(rename = "redemption period")]
    RedemptionPeriod,
    #[serde(rename = "renew period")]
    RenewPeriod,
    #[serde(rename = "server delete prohibited")]
    ServerDeleteProhibited,
    #[serde(rename = "server renew prohibited")]
    ServerRenewProhibited,
    #[serde(rename = "server transfer prohibited")]
    ServerTransferProhibited,
    #[serde(rename = "server update prohibited")]
    ServerUpdateProhibited,
    #[serde(rename = "server hold")]
    ServerHold,
    #[serde(rename = "transfer period")]
    TransferPeriod,
    // Non standard
    /// Non standard 'flir' domain registry status for nameservers.
    Ok,
}

#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug)]
pub struct IpAddresses {
    pub v4: Option<Vec<Ipv4Addr>>,
    pub v6: Option<Vec<Ipv6Addr>>,
}

/// https://tools.ietf.org/html/rfc7483#section-5.2
#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Nameserver {
    pub handle: Option<String>,
    pub ldh_name: String,
    pub unicode_name: Option<String>,
    pub ip_addresses: Option<IpAddresses>,
    pub entities: Option<Vec<Entity>>,
    pub status: Option<Vec<Status>>,
    pub remarks: Option<NoticesOrRemarks>,
    pub notices: Option<NoticesOrRemarks>,
    pub links: Option<Vec<Link>>,
    pub object_class_name: String,
}

/// https://tools.ietf.org/html/rfc7483#section-10.2.3 and https://www.iana.org/assignments/rdap-json-values/rdap-json-values.xhtml
#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone, Copy)]
#[serde(rename_all = "lowercase")]
#[serde(remote = "EventAction")]
pub enum EventAction {
    Registration,
    Reregistration,
    #[serde(rename = "last changed")]
    LastChanged,
    Expiration,
    Deletion,
    Reinstantiation,
    Transfer,
    Locked,
    Unlocked,
    // Extensions
    #[serde(rename = "last update of RDAP database")]
    /// From 'icann_rdap_response_profile_0' extension.
    LastUpdateOfRdapDatabase,
    #[serde(rename = "registrar expiration")]
    /// From 'icann_rdap_response_profile_0' extension.
    RegistrarExpiration,
    #[serde(rename = "enum validation expiration")]
    /// From 'fred' extension.
    EnumValidationExpiration,
    // Non standard
    #[serde(rename = "delegation sign check")]
    /// Non standard value from `final` domain RDAP.
    DelegationSignCheck,
    #[serde(rename = "soft expiration")]
    /// Non standard value from `is` domain RDAP.
    SoftExpiration,
    #[serde(rename = "last correct delegation sign check")]
    /// Non standard value from `br` domain RDAP.
    LastCorrectDelegationSignCheck,
}

impl<'de> Deserialize<'de> for EventAction {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = deserialize_string_lowercase(deserializer)?;
        if s == "last update of rdap database" {
            // Because original string is converted to lowercase and the original value contains
            // uppercase word 'RDAP', we need to compare this value manually.
            Ok(Self::LastUpdateOfRdapDatabase)
        } else {
            Self::deserialize(s.into_deserializer())
        }
    }
}

impl Serialize for EventAction {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        Self::serialize(self, serializer)
    }
}

/// https://tools.ietf.org/html/rfc7483#section-4.5
#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Event {
    pub event_actor: Option<String>,
    pub event_action: EventAction,
    #[serde(deserialize_with = "deserialize_datetime")]
    pub event_date: DateTime<FixedOffset>,
    pub links: Option<Link>,
}

#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug)]
pub struct Events(Vec<Event>);

impl Events {
    pub fn action_date(&self, action: EventAction) -> Option<DateTime<FixedOffset>> {
        self.0
            .iter()
            .find(|p| p.event_action == action)
            .map(|e| e.event_date)
    }
}

impl<'a> IntoIterator for &'a Events {
    type Item = &'a Event;
    type IntoIter = Iter<'a, Event>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

/// https://tools.ietf.org/html/rfc7483#section-10.2.1 and https://www.iana.org/assignments/rdap-json-values/rdap-json-values.xhtml
#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone, Copy)]
#[serde(remote = "NoticeOrRemarkType")]
pub enum NoticeOrRemarkType {
    #[serde(rename = "result set truncated due to authorization")]
    ResultSetTruncatedDueToAuthorization,
    #[serde(rename = "result set truncated due to excessive load")]
    ResultSetTruncatedDueToExcessiveLoad,
    #[serde(rename = "result set truncated due to unexplainable reasons")]
    ResultSetTruncatedDueToUnexplainableReasons,
    #[serde(rename = "object truncated due to authorization")]
    ObjectTruncatedDueToAuthorization,
    #[serde(rename = "object truncated due to excessive load")]
    ObjectTruncatedDueToExcessiveLoad,
    #[serde(rename = "object truncated due to unexplainable reasons")]
    ObjectTruncatedDueToUnexplainableReasons,
    // Extensions
    #[serde(rename = "object redacted due to authorization")]
    /// Value from 'icann_rdap_response_profile_0' extension.
    ObjectRedactedDueToAuthorization,
    // Non standards
    #[serde(rename = "object truncated due to server policy")]
    ObjectTruncatedDueToServerPolicy,
    #[serde(rename = "response truncated due to authorization")]
    /// Non standard value from 'abudhabi' domain registry.
    ResponseTruncatedDueToAuthorization,
}

impl<'de> Deserialize<'de> for NoticeOrRemarkType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = deserialize_string_lowercase(deserializer)?;
        if s == "object redacted due to authorization." {
            // `lat` domain registry contains typo and value ends with dot :/
            Ok(Self::ObjectRedactedDueToAuthorization)
        } else {
            Self::deserialize(s.into_deserializer())
        }
    }
}

impl Serialize for NoticeOrRemarkType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        Self::serialize(self, serializer)
    }
}

#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug)]
pub struct NoticeOrRemark {
    pub title: Option<String>,
    #[serde(rename = "type")]
    pub typ: Option<NoticeOrRemarkType>,
    pub description: Option<Vec<String>>,
    pub links: Option<Vec<Link>>,
}

#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug)]
pub struct NoticesOrRemarks(Vec<NoticeOrRemark>);

impl NoticesOrRemarks {
    pub fn description_by_title(&self, title: &str) -> Option<&Vec<String>> {
        for remark in self.0.iter().filter(|p| p.description.is_some()) {
            if let Some(t) = &remark.title {
                if title.eq_ignore_ascii_case(t.as_str()) {
                    return remark.description.as_ref();
                }
            } else if title == "remarks" {
                return remark.description.as_ref();
            }
        }

        None
    }
}

impl<'a> IntoIterator for &'a NoticesOrRemarks {
    type Item = &'a NoticeOrRemark;
    type IntoIter = Iter<'a, NoticeOrRemark>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

/// An enum signifying the IP protocol version of the network: "v4" signifies an IPv4 network,
/// and "v6" signifies an IPv6 network.
#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone, Copy)]
#[serde(rename_all = "camelCase")]
pub enum IpVersion {
    V4,
    V6,
}

/// From 'cidr0' extension. https://bitbucket.org/nroecg/nro-rdap-cidr/src/master/nro-rdap-cidr.txt
#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug)]
pub struct CidrOCidr {
    pub v4prefix: Option<Ipv4Addr>,
    pub v6prefix: Option<Ipv6Addr>,
    pub length: u8,
}

#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct IpNetwork {
    pub handle: String,
    pub start_address: IpAddr,
    pub end_address: IpAddr,
    pub ip_version: IpVersion,
    pub name: Option<String>,
    pub country: Option<CountryCode>,
    pub parent_handle: Option<String>,
    #[serde(rename = "type")]
    pub typ: Option<String>,
    pub entities: Option<Vec<Entity>>,
    pub links: Option<Vec<Link>>,
    pub remarks: Option<NoticesOrRemarks>,
    pub events: Option<Events>,
    pub rdap_conformance: Option<Vec<String>>,
    pub notices: Option<NoticesOrRemarks>,
    pub port43: Option<String>,
    pub status: Option<Vec<Status>>,
    pub lang: Option<String>,
    pub object_class_name: String,
    // cidr0 extension
    #[serde(rename = "cidr0_cidrs")]
    pub cidr0_cidrs: Option<Vec<CidrOCidr>>,
    /// From 'arin_originas0' extension.
    #[serde(rename = "arin_originas0_originautnums")]
    pub arin_originas0_originautnums: Option<Vec<u32>>,
}

/// https://tools.ietf.org/html/rfc7483#section-5.5
#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct AutNum {
    pub handle: String,
    pub start_autnum: Option<u32>,
    pub end_autnum: Option<u32>,
    pub name: Option<String>,
    pub country: Option<CountryCode>,
    #[serde(rename = "type")]
    pub typ: Option<String>,
    pub entities: Vec<Entity>,
    pub links: Option<Vec<Link>>,
    pub remarks: Option<NoticesOrRemarks>,
    pub events: Option<Events>,
    pub rdap_conformance: Option<Vec<String>>,
    pub notices: Option<NoticesOrRemarks>,
    pub port43: Option<String>,
    pub status: Option<Vec<Status>>,
    pub lang: Option<String>,
    pub object_class_name: String,
}

/// https://tools.ietf.org/html/rfc7483#section-10.2.5
#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "lowercase")]
enum DomainVariantRelation {
    Registered,
    Unregistered,
    #[serde(rename = "registration restricted")]
    RegistrationRestricted,
    #[serde(rename = "open registration")]
    OpenRegistration,
    Conjoined,
}

#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct VariantName {
    ldh_name: String,
    unicode_name: String,
}

#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Variant {
    relation: Vec<DomainVariantRelation>,
    idn_table: Option<String>,
    variant_names: Vec<VariantName>,
}

/// For field sizes see https://tools.ietf.org/html/rfc4034#section-5.1
#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct DsData {
    key_tag: Option<u16>,
    algorithm: u8,
    digest: String,
    digest_type: u8,
    events: Option<Events>,
    links: Option<Vec<Link>>,
}

/// For field sizes see https://tools.ietf.org/html/rfc4034#section-2.1
#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct KeyData {
    flags: u16,
    protocol: u8,
    public_key: String,
    algorithm: u8,
    events: Option<Events>,
    links: Option<Vec<Link>>,
}

#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct SecureDns {
    zone_signed: Option<bool>,
    delegation_signed: Option<bool>,
    max_sig_life: Option<u32>,
    ds_data: Option<Vec<DsData>>,
    key_data: Option<Vec<KeyData>>,
}

/// https://fred.nic.cz/rdap-extension/
#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct FredKeyset {
    pub links: Vec<Link>,
    pub handle: String,
    pub object_class_name: String,
    #[serde(rename = "dns_keys")]
    pub dns_keys: Vec<KeyData>,
}

/// https://fred.nic.cz/rdap-extension/
#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct FredNsset {
    pub links: Vec<Link>,
    pub handle: String,
    pub object_class_name: String,
    pub nameservers: Vec<Nameserver>,
}

/// https://tools.ietf.org/html/rfc7483#section-5.3
#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Domain {
    pub handle: Option<String>,
    pub entities: Vec<Entity>,
    pub links: Option<Vec<Link>>,
    pub variants: Option<Vec<Variant>>,
    pub nameservers: Option<Vec<Nameserver>>,
    #[serde(rename = "secureDNS")]
    pub secure_dns: Option<SecureDns>,
    pub remarks: Option<NoticesOrRemarks>,
    pub events: Events,
    pub network: Option<IpNetwork>,
    pub rdap_conformance: Option<Vec<String>>,
    pub notices: Option<NoticesOrRemarks>,
    pub port43: Option<String>,
    pub status: Option<Vec<String>>,
    pub lang: Option<String>,
    pub object_class_name: String,
    // fred extension
    #[serde(rename = "fred_keyset")]
    pub fred_keyset: Option<FredKeyset>,
    #[serde(rename = "fred_nsset")]
    pub fred_nsset: Option<FredNsset>,
}

/// https://tools.ietf.org/html/rfc7483.html#section-7
#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Help {
    rdap_conformance: Option<Vec<String>>,
    notices: Option<NoticesOrRemarks>,
}

// https://tools.ietf.org/html/rfc7483#section-8
#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct EntitySearchResults {
    rdap_conformance: Option<Vec<String>>,
    notices: Option<NoticesOrRemarks>,
    #[serde(rename = "entitySearchResults")]
    results: Vec<Entity>,
}

#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct DomainSearchResults {
    rdap_conformance: Option<Vec<String>>,
    notices: Option<NoticesOrRemarks>,
    #[serde(rename = "domainSearchResults")]
    results: Vec<Entity>,
}

#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct NameserverSearchResults {
    rdap_conformance: Option<Vec<String>>,
    notices: Option<NoticesOrRemarks>,
    #[serde(rename = "nameserverSearchResults")]
    results: Vec<Entity>,
}

#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ArinOriginas0OriginautnumsResults {
    rdap_conformance: Option<Vec<String>>,
    notices: Option<NoticesOrRemarks>,
    #[serde(rename = "arin_originas0_networkSearchResults")]
    results: Vec<IpNetwork>,
}

// Some servers returns error code as string, so this function can deserialize
// both number in string form and unsigned integer.
fn deserialize_error_code<'de, D>(deserializer: D) -> Result<u16, D::Error>
where
    D: Deserializer<'de>,
{
    struct ErrorCodeVisitor;

    impl<'de> Visitor<'de> for ErrorCodeVisitor {
        type Value = u16;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(formatter, "expecting an error code as string or number")
        }

        fn visit_u64<E>(self, v: u64) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            u16::try_from(v).map_err(|_| {
                serde::de::Error::invalid_value(Unexpected::Unsigned(v), &"an error code")
            })
        }

        fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            u16::from_str(v)
                .map_err(|_| serde::de::Error::invalid_value(Unexpected::Str(v), &"an error code"))
        }
    }

    deserializer.deserialize_any(ErrorCodeVisitor)
}

/// https://tools.ietf.org/html/rfc7483#section-6
#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Error {
    #[serde(deserialize_with = "deserialize_error_code")]
    error_code: u16,
    title: String,
    description: Option<Vec<String>>,
    rdap_conformance: Option<Vec<String>>,
    notices: Option<NoticesOrRemarks>,
    lang: Option<String>,
}

pub trait BootstrapService {
    fn keys(&self) -> &Vec<String>;
    fn servers(&self) -> &Vec<String>;
}

#[derive(Deserialize, Debug)]
pub struct BootstrapServiceRfc7484(Vec<String>, Vec<String>);

impl BootstrapService for BootstrapServiceRfc7484 {
    fn keys(&self) -> &Vec<String> {
        &self.0
    }
    fn servers(&self) -> &Vec<String> {
        &self.1
    }
}

#[derive(Deserialize, Debug)]
pub struct BootstrapServiceRfc8521(Vec<String>, Vec<String>, Vec<String>);

impl BootstrapService for BootstrapServiceRfc8521 {
    fn keys(&self) -> &Vec<String> {
        &self.1
    }
    fn servers(&self) -> &Vec<String> {
        &self.2
    }
}

#[derive(Deserialize, Debug)]
pub struct Bootstrap<T> {
    pub description: Option<String>,
    pub publication: DateTime<FixedOffset>,
    pub services: Vec<T>,
    pub version: String,
}

/// Bootstrap response that follows definition from RFC 7484.
pub type BootstrapRfc7484 = Bootstrap<BootstrapServiceRfc7484>;
/// Bootstrap response that follows definition from RFC 8521 (object tags).
pub type BootstrapRfc8521 = Bootstrap<BootstrapServiceRfc8521>;

#[cfg(test)]
mod tests {
    use super::*;
    use serde::de::DeserializeOwned;
    use std::fs::File;

    #[test]
    fn test_county_code() {
        let country_code = CountryCode::from_str("CZ").unwrap();
        assert_eq!(country_code.to_string(), "CZ");
        assert_eq!(format!("{:?}", country_code), "CZ");
        assert_eq!(country_code, CountryCode::from_str("cz").unwrap());

        assert!(CountryCode::from_str("CZE").is_err());
        assert!(CountryCode::from_str("C").is_err());
        assert!(CountryCode::from_str("ČZ").is_err());
    }

    #[test]
    fn test_country_code_serialize_deserialize() {
        let item: CountryCode = serde_json::from_str(&"\"CZ\"").unwrap();
        assert_eq!(item, CountryCode::from_str("CZ").unwrap());

        let json = serde_json::to_string(&item).unwrap();
        assert_eq!(json, "\"CZ\"");
    }

    #[test]
    fn test_normalize_enum() {
        let item: JCardItemDataType = serde_json::from_str(&"\"uri\"").unwrap();
        assert_eq!(item, JCardItemDataType::Uri);

        let item: JCardItemDataType = serde_json::from_str(&"\"URI\"").unwrap();
        assert_eq!(item, JCardItemDataType::Uri);

        let json = serde_json::to_string(&JCardItemDataType::Uri).unwrap();
        assert_eq!(json, "\"uri\"");
    }

    #[test]
    fn parse_vcard_multiple_values() {
        let json = r#"["vcard",[["version",{},"text","4.0"],["fn",{},"text",""],["adr",{"cc":"US","iso-3166-1-alpha-2":"US"},"text","","","","","Washington","",""],["org",{},"text","Amazon Registry Services, Inc."]]]"#;
        let jcard: JCard = serde_json::from_str(&json).unwrap();
        assert_eq!(jcard.typ(), JCardType::Vcard);
        assert_eq!(jcard.items().len(), 4);

        assert_eq!(jcard.items_by_name("adr")[0].values.len(), 7);
        assert_eq!(
            jcard.items_by_name("org")[0].values[0],
            "Amazon Registry Services, Inc."
        );

        let ser_json = serde_json::to_string(&jcard).unwrap();
        assert_eq!(json, ser_json);
    }

    #[test]
    fn test_event_date_normal_format() {
        let json = r#"{"eventDate":"1990-12-31T23:59:59Z","eventAction":"last changed"}"#;
        let item: Event = serde_json::from_str(&json).unwrap();
        assert_eq!(item.event_date.to_rfc3339(), "1990-12-31T23:59:59+00:00");
    }

    #[test]
    fn test_event_date_normal_format_with_timezone() {
        let json = r#"{"eventDate":"2011-07-05T12:48:24-04:00","eventAction":"last changed"}"#;
        let item: Event = serde_json::from_str(&json).unwrap();
        assert_eq!(item.event_date.to_rfc3339(), "2011-07-05T12:48:24-04:00");
    }

    #[test]
    fn test_event_date_weird_format() {
        let json = r#"{"eventDate":"2019-09-20T11:45:06","eventAction":"last changed"}"#;
        let item: Event = serde_json::from_str(&json).unwrap();
        assert_eq!(item.event_date.to_rfc3339(), "2019-09-20T11:45:06+00:00");
    }

    // xn--rhqv96g domain registry format
    #[test]
    fn test_event_date_weird_format_vol2() {
        let json = r#"{"eventAction":"last changed","eventDate":"2016-04-13 08:18:43"}"#;
        let item: Event = serde_json::from_str(&json).unwrap();
        assert_eq!(item.event_date.to_rfc3339(), "2016-04-13T08:18:43+00:00");
    }

    // `mtr` domain registry format
    #[test]
    fn test_event_date_weird_format_vol3() {
        let json = r#"{"eventAction":"last changed","eventDate":"2015-08-25T00:00:00Z+0800"}"#;
        let item: Event = serde_json::from_str(&json).unwrap();
        assert_eq!(item.event_date.to_rfc3339(), "2015-08-25T00:00:00+08:00");
    }

    #[test]
    fn test_notices_or_remarks() {
        let notices_or_remarks = NoticesOrRemarks(vec![NoticeOrRemark {
            title: Some("Title".into()),
            typ: None,
            description: Some(vec!["Ahoj".into()]),
            links: None,
        }]);
        assert_eq!(
            notices_or_remarks.description_by_title("title").unwrap()[0],
            "Ahoj"
        );
        assert!(notices_or_remarks.description_by_title("nothing").is_none());
    }

    fn deserialize<T: DeserializeOwned>(path: &str) -> T {
        let file = File::open(format!("test_data/{}", path)).unwrap();
        let parsed: T = serde_json::from_reader(file).unwrap();
        parsed
    }

    fn deserialize_and_serialize<T: DeserializeOwned + Serialize>(path: &str) -> T {
        let parsed = deserialize(path);
        // And convert back to JSON
        serde_json::to_string(&parsed).unwrap();
        parsed
    }

    #[test]
    fn test_parse_entity_15() {
        let parsed: Entity = deserialize_and_serialize("entity/entity_15.json");
        assert_eq!("XXXX", parsed.handle.as_ref().unwrap());
        assert_eq!(1, parsed.as_event_actor.as_ref().unwrap().0.len());
    }

    #[test]
    fn test_parse_entity_17() {
        let parsed: Entity = deserialize_and_serialize("entity/entity_17.json");
        assert_eq!("XXXX", parsed.handle.as_ref().unwrap());
    }

    #[test]
    fn test_parse_entity_fred() {
        let parsed: Entity = deserialize_and_serialize("entity/entity_fred.json");
        assert_eq!("CZ-NIC", parsed.handle.as_ref().unwrap());
    }

    #[test]
    fn test_parse_entity_ripe() {
        let parsed: Entity = deserialize_and_serialize("entity/entity_ripe.json");
        assert_eq!("ORG-RIEN1-RIPE", parsed.handle.as_ref().unwrap());
    }

    #[test]
    fn test_parse_nameserver_18() {
        let parsed: Nameserver = deserialize_and_serialize("nameserver/nameserver_18.json");
        assert_eq!("XXXX", parsed.handle.unwrap());
    }

    #[test]
    fn test_parse_nameserver_19() {
        let parsed: Nameserver = deserialize_and_serialize("nameserver/nameserver_19.json");
        assert_eq!("ns1.example.com", parsed.ldh_name);
    }

    #[test]
    fn test_parse_nameserver_20() {
        let parsed: Nameserver = deserialize_and_serialize("nameserver/nameserver_20.json");
        assert_eq!("ns1.example.com", parsed.ldh_name);
    }

    #[test]
    fn test_parse_nameserver_fred() {
        let parsed: Nameserver = deserialize_and_serialize("nameserver/nameserver_fred.json");
        assert_eq!("a.ns.nic.cz", parsed.ldh_name);
    }

    #[test]
    fn test_parse_domain_23() {
        let parsed: Domain = deserialize_and_serialize("domain/domain_23.json");
        assert_eq!("XXXX", parsed.handle.unwrap());
    }

    #[test]
    fn test_parse_domain_24() {
        let parsed: Domain = deserialize_and_serialize("domain/domain_24.json");
        assert_eq!("XXXX", parsed.handle.unwrap());
    }

    #[test]
    fn test_parse_domain_fred() {
        let parsed: Domain = deserialize_and_serialize("domain/domain_fred.json");
        assert_eq!("nic.cz", parsed.handle.unwrap());
    }

    #[test]
    fn test_parse_domain_ripe_reverse() {
        let parsed: Domain = deserialize_and_serialize("domain/domain_ripe_reverse.json");
        assert_eq!("6.0.193.in-addr.arpa", parsed.handle.unwrap());
    }

    #[test]
    fn test_parse_ip_network_26() {
        let parsed: IpNetwork = deserialize_and_serialize("ip_network/ip_network_26.json");
        assert_eq!("XXXX-RIR", parsed.handle);
    }

    #[test]
    fn test_parse_ip_network_apnic_1_1_1_1() {
        let parsed: IpNetwork =
            deserialize_and_serialize("ip_network/ip_network_apnic_1_1_1_1.json");
        assert_eq!("1.1.1.0 - 1.1.1.255", parsed.handle);
    }

    #[test]
    fn test_parse_ip_network_arin_3_3_3_3() {
        let parsed: IpNetwork =
            deserialize_and_serialize("ip_network/ip_network_arin_3_3_3_3.json");
        assert_eq!("NET-3-0-0-0-1", parsed.handle);
    }

    #[test]
    fn test_parse_ip_network_ripe_193_0_0_0() {
        let parsed: IpNetwork =
            deserialize_and_serialize("ip_network/ip_network_ripe_193_0_0_0.json");
        assert_eq!("193.0.0.0 - 193.0.7.255", parsed.handle);
    }

    #[test]
    fn test_parse_ip_network_afrinic() {
        let parsed: IpNetwork = deserialize_and_serialize("ip_network/ip_network_afrinic.json");
        assert_eq!("41.0.0.0 - 41.0.255.255", parsed.handle);
    }

    #[test]
    fn test_parse_ip_network_br() {
        let parsed: IpNetwork = deserialize_and_serialize("ip_network/ip_network_br.json");
        assert_eq!("177.0.0.0/14", parsed.handle);
    }

    #[test]
    fn test_parse_ip_network_lacnic() {
        let parsed: IpNetwork = deserialize_and_serialize("ip_network/ip_network_lacnic.json");
        assert_eq!("179.0.0.0/23", parsed.handle);
    }

    #[test]
    fn test_parse_autnum_27() {
        let parsed: AutNum = deserialize_and_serialize("autnum/autnum_27.json");
        assert_eq!("XXXX-RIR", parsed.handle);
    }

    #[test]
    fn test_parse_autnum_ripe_as1234() {
        let parsed: AutNum = deserialize_and_serialize("autnum/autnum_ripe_as1234.json");
        assert_eq!("AS1234", parsed.handle);
    }

    #[test]
    fn test_parse_autnum_arin_as256() {
        let parsed: AutNum = deserialize_and_serialize("autnum/autnum_arin_as256.json");
        assert_eq!("AS256", parsed.handle);
    }

    #[test]
    fn test_parse_autnum_afrinic_as36864() {
        let parsed: AutNum = deserialize_and_serialize("autnum/autnum_afrinic_as36864.json");
        assert_eq!("AS36864", parsed.handle);
    }

    #[test]
    fn test_parse_autnum_apnic_as4608() {
        let parsed: AutNum = deserialize_and_serialize("autnum/autnum_apnic_as4608.json");
        assert_eq!("AS4608", parsed.handle);
    }

    #[test]
    fn test_parse_autnum_lacnic_as27648() {
        let parsed: AutNum = deserialize_and_serialize("autnum/autnum_lacnic_as27648.json");
        assert_eq!("27648", parsed.handle);
    }

    #[test]
    fn test_parse_arin_originas0_network_search_results() {
        let parsed: ArinOriginas0OriginautnumsResults =
            deserialize_and_serialize("arin_originas0_networkSearchResults.json");
        assert!(parsed.results.len() > 0);
    }

    #[test]
    fn test_parse_error_28() {
        let parsed: Error = deserialize_and_serialize("error/error_28.json");
        assert_eq!(418, parsed.error_code);
    }

    #[test]
    fn test_parse_error_29() {
        let parsed: Error = deserialize_and_serialize("error/error_29.json");
        assert_eq!(418, parsed.error_code);
    }

    #[test]
    fn test_parse_error_apnic_400() {
        let parsed: Error = deserialize_and_serialize("error/error_apnic_400.json");
        assert_eq!(400, parsed.error_code);
    }

    #[test]
    fn test_parse_error_ripe_404() {
        let parsed: Error = deserialize_and_serialize("error/error_ripe_404.json");
        assert_eq!(404, parsed.error_code);
    }

    #[test]
    fn test_parse_bootstrap_asn() {
        let parsed: BootstrapRfc7484 = deserialize("bootstrap/asn.json");
        assert!(parsed.services.len() > 0);
    }

    #[test]
    fn test_parse_bootstrap_dns() {
        let parsed: BootstrapRfc7484 = deserialize("bootstrap/dns.json");
        assert!(parsed.services.len() > 0);
    }

    #[test]
    fn test_parse_bootstrap_ipv4() {
        let parsed: BootstrapRfc7484 = deserialize("bootstrap/ipv4.json");
        assert!(parsed.services.len() > 0);
    }

    #[test]
    fn test_parse_bootstrap_ipv6() {
        let parsed: BootstrapRfc7484 = deserialize("bootstrap/ipv6.json");
        assert!(parsed.services.len() > 0);
    }

    #[test]
    fn test_parse_bootstrap_object_tags() {
        let parsed: BootstrapRfc8521 = deserialize("bootstrap/object-tags.json");
        assert!(parsed.services.len() > 0);
    }
}
