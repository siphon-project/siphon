//! Diameter AVP dictionary for SIPhon.
//!
//! Static lookup table of AVP definitions covering:
//!   - Base Diameter (RFC 6733)
//!   - Credit-Control / Gy (RFC 4006)
//!   - 3GPP Cx/Dx (TS 29.228/229) and Sh (TS 29.329) — IMS
//!   - 3GPP S6a (TS 29.272) — EPC
//!   - 3GPP Gx (TS 29.212) and Rx (TS 29.214) — Policy
//!   - 3GPP Ro/Rf (TS 32.299) — IMS Online/Offline Charging

/// How an AVP value is encoded on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AvpType {
    OctetString,
    UTF8String,
    Unsigned32,
    Unsigned64,
    Integer32,
    Enumerated,
    Grouped,
    Address,
    Time,
    DiameterIdentity,
}

impl AvpType {
    /// Whether this type contains nested AVPs.
    pub fn is_container(&self) -> bool {
        matches!(self, AvpType::Grouped)
    }

    /// Whether this type is text-representable (UTF8String or DiameterIdentity).
    pub fn is_text(&self) -> bool {
        matches!(self, AvpType::UTF8String | AvpType::DiameterIdentity)
    }
}

/// A single AVP definition: code + vendor + human name + wire type.
#[derive(Debug, Clone, Copy)]
pub struct AvpDef {
    pub code: u32,
    pub vendor_id: u32,
    pub name: &'static str,
    pub data_type: AvpType,
}

impl AvpDef {
    /// Whether this AVP is vendor-specific (vendor_id != 0).
    pub fn is_vendor_specific(&self) -> bool {
        self.vendor_id != 0
    }
}

/// 3GPP vendor identifier (IANA enterprise number 10415).
const TGPP: u32 = 10415;

/// Sorted by (vendor_id, code) for binary search.
static AVP_TABLE: &[AvpDef] = &[
    // ── Base Diameter (RFC 6733), vendor_id = 0 ─────────────────────────────
    AvpDef { code: 1,   vendor_id: 0, name: "User-Name",                    data_type: AvpType::UTF8String },
    AvpDef { code: 8,   vendor_id: 0, name: "Framed-IP-Address",            data_type: AvpType::OctetString },
    AvpDef { code: 25,  vendor_id: 0, name: "Class",                        data_type: AvpType::OctetString },
    AvpDef { code: 27,  vendor_id: 0, name: "Session-Timeout",              data_type: AvpType::Unsigned32 },
    AvpDef { code: 33,  vendor_id: 0, name: "Proxy-State",                  data_type: AvpType::OctetString },
    AvpDef { code: 44,  vendor_id: 0, name: "Acct-Session-Id",              data_type: AvpType::OctetString },
    AvpDef { code: 50,  vendor_id: 0, name: "Acct-Multi-Session-Id",        data_type: AvpType::UTF8String },
    AvpDef { code: 55,  vendor_id: 0, name: "Event-Timestamp",              data_type: AvpType::Time },
    AvpDef { code: 97,  vendor_id: 0, name: "Framed-IPv6-Prefix",           data_type: AvpType::OctetString },
    AvpDef { code: 257, vendor_id: 0, name: "Host-IP-Address",              data_type: AvpType::Address },
    AvpDef { code: 258, vendor_id: 0, name: "Auth-Application-Id",          data_type: AvpType::Unsigned32 },
    AvpDef { code: 259, vendor_id: 0, name: "Acct-Application-Id",          data_type: AvpType::Unsigned32 },
    AvpDef { code: 260, vendor_id: 0, name: "Vendor-Specific-Application-Id", data_type: AvpType::Grouped },
    AvpDef { code: 263, vendor_id: 0, name: "Session-Id",                   data_type: AvpType::UTF8String },
    AvpDef { code: 264, vendor_id: 0, name: "Origin-Host",                  data_type: AvpType::DiameterIdentity },
    AvpDef { code: 265, vendor_id: 0, name: "Supported-Vendor-Id",          data_type: AvpType::Unsigned32 },
    AvpDef { code: 266, vendor_id: 0, name: "Vendor-Id",                    data_type: AvpType::Unsigned32 },
    AvpDef { code: 267, vendor_id: 0, name: "Firmware-Revision",            data_type: AvpType::Unsigned32 },
    AvpDef { code: 268, vendor_id: 0, name: "Result-Code",                  data_type: AvpType::Unsigned32 },
    AvpDef { code: 269, vendor_id: 0, name: "Product-Name",                 data_type: AvpType::UTF8String },
    AvpDef { code: 270, vendor_id: 0, name: "Session-Binding",              data_type: AvpType::Unsigned32 },
    AvpDef { code: 274, vendor_id: 0, name: "Auth-Grace-Period",            data_type: AvpType::Unsigned32 },
    AvpDef { code: 277, vendor_id: 0, name: "Auth-Session-State",           data_type: AvpType::Enumerated },
    AvpDef { code: 278, vendor_id: 0, name: "Origin-State-Id",              data_type: AvpType::Unsigned32 },
    AvpDef { code: 279, vendor_id: 0, name: "Failed-AVP",                   data_type: AvpType::Grouped },
    AvpDef { code: 281, vendor_id: 0, name: "Error-Message",                data_type: AvpType::UTF8String },
    AvpDef { code: 282, vendor_id: 0, name: "Route-Record",                 data_type: AvpType::DiameterIdentity },
    AvpDef { code: 283, vendor_id: 0, name: "Destination-Realm",            data_type: AvpType::DiameterIdentity },
    AvpDef { code: 284, vendor_id: 0, name: "Proxy-Info",                   data_type: AvpType::Grouped },
    AvpDef { code: 285, vendor_id: 0, name: "Re-Auth-Request-Type",         data_type: AvpType::Enumerated },
    AvpDef { code: 291, vendor_id: 0, name: "Authorization-Lifetime",       data_type: AvpType::Unsigned32 },
    AvpDef { code: 293, vendor_id: 0, name: "Destination-Host",             data_type: AvpType::DiameterIdentity },
    AvpDef { code: 296, vendor_id: 0, name: "Origin-Realm",                 data_type: AvpType::DiameterIdentity },
    AvpDef { code: 297, vendor_id: 0, name: "Experimental-Result",          data_type: AvpType::Grouped },
    AvpDef { code: 298, vendor_id: 0, name: "Experimental-Result-Code",     data_type: AvpType::Unsigned32 },
    AvpDef { code: 299, vendor_id: 0, name: "Inband-Security-Id",           data_type: AvpType::Unsigned32 },

    // ── RFC 4006 Credit-Control (Gy), vendor_id = 0 ────────────────────────
    AvpDef { code: 415, vendor_id: 0, name: "CC-Request-Type",              data_type: AvpType::Enumerated },
    AvpDef { code: 416, vendor_id: 0, name: "CC-Request-Number",            data_type: AvpType::Unsigned32 },
    AvpDef { code: 421, vendor_id: 0, name: "CC-Sub-Session-Id",            data_type: AvpType::Unsigned64 },
    AvpDef { code: 426, vendor_id: 0, name: "Granted-Service-Unit",         data_type: AvpType::Grouped },
    AvpDef { code: 427, vendor_id: 0, name: "Rating-Group",                 data_type: AvpType::Unsigned32 },
    AvpDef { code: 431, vendor_id: 0, name: "Final-Unit-Indication",        data_type: AvpType::Grouped },
    AvpDef { code: 432, vendor_id: 0, name: "Final-Unit-Action",            data_type: AvpType::Enumerated },
    AvpDef { code: 437, vendor_id: 0, name: "Requested-Service-Unit",       data_type: AvpType::Grouped },
    AvpDef { code: 443, vendor_id: 0, name: "Subscription-Id",              data_type: AvpType::Grouped },
    AvpDef { code: 444, vendor_id: 0, name: "Subscription-Id-Data",         data_type: AvpType::UTF8String },
    AvpDef { code: 446, vendor_id: 0, name: "Used-Service-Unit",            data_type: AvpType::Grouped },
    AvpDef { code: 448, vendor_id: 0, name: "Validity-Time",                data_type: AvpType::Unsigned32 },
    AvpDef { code: 450, vendor_id: 0, name: "Subscription-Id-Type",         data_type: AvpType::Enumerated },
    AvpDef { code: 452, vendor_id: 0, name: "Tariff-Change-Usage",          data_type: AvpType::Enumerated },
    AvpDef { code: 454, vendor_id: 0, name: "CC-Time",                      data_type: AvpType::Unsigned32 },
    AvpDef { code: 455, vendor_id: 0, name: "CC-Money",                     data_type: AvpType::Grouped },
    AvpDef { code: 456, vendor_id: 0, name: "CC-Total-Octets",              data_type: AvpType::Unsigned64 },
    AvpDef { code: 457, vendor_id: 0, name: "CC-Input-Octets",              data_type: AvpType::Unsigned64 },
    AvpDef { code: 458, vendor_id: 0, name: "CC-Output-Octets",             data_type: AvpType::Unsigned64 },
    AvpDef { code: 459, vendor_id: 0, name: "CC-Service-Specific-Units",    data_type: AvpType::Unsigned64 },
    AvpDef { code: 461, vendor_id: 0, name: "Service-Identifier",           data_type: AvpType::Unsigned32 },
    AvpDef { code: 480, vendor_id: 0, name: "Accounting-Record-Type",       data_type: AvpType::Enumerated },
    AvpDef { code: 485, vendor_id: 0, name: "Accounting-Record-Number",     data_type: AvpType::Unsigned32 },

    // ── 3GPP AVPs, vendor_id = 10415 (sorted by code) ─────────────────────

    // S6a common
    AvpDef { code: 493,  vendor_id: TGPP, name: "Service-Selection",                  data_type: AvpType::UTF8String },
    // Rx (TS 29.214)
    AvpDef { code: 501,  vendor_id: TGPP, name: "Access-Network-Charging-Address",    data_type: AvpType::Address },
    AvpDef { code: 502,  vendor_id: TGPP, name: "Access-Network-Charging-Identifier", data_type: AvpType::Grouped },
    AvpDef { code: 504,  vendor_id: TGPP, name: "AF-Application-Identifier",          data_type: AvpType::OctetString },
    AvpDef { code: 505,  vendor_id: TGPP, name: "AF-Charging-Identifier",             data_type: AvpType::OctetString },
    AvpDef { code: 507,  vendor_id: TGPP, name: "Flow-Description",                   data_type: AvpType::OctetString },
    AvpDef { code: 508,  vendor_id: TGPP, name: "Flow-Number",                        data_type: AvpType::Unsigned32 },
    AvpDef { code: 509,  vendor_id: TGPP, name: "Flows",                              data_type: AvpType::Grouped },
    AvpDef { code: 510,  vendor_id: TGPP, name: "Flow-Status",                        data_type: AvpType::Enumerated },
    AvpDef { code: 511,  vendor_id: TGPP, name: "Flow-Usage",                         data_type: AvpType::Enumerated },
    AvpDef { code: 512,  vendor_id: TGPP, name: "Specific-Action",                    data_type: AvpType::Enumerated },
    AvpDef { code: 513,  vendor_id: TGPP, name: "Max-Requested-Bandwidth-DL-Rx",      data_type: AvpType::Unsigned32 },
    AvpDef { code: 514,  vendor_id: TGPP, name: "Max-Requested-Bandwidth-UL-Rx",      data_type: AvpType::Unsigned32 },
    AvpDef { code: 515,  vendor_id: TGPP, name: "Media-Component-Description",        data_type: AvpType::Grouped },
    AvpDef { code: 517,  vendor_id: TGPP, name: "Media-Component-Number",             data_type: AvpType::Unsigned32 },
    AvpDef { code: 518,  vendor_id: TGPP, name: "Media-Sub-Component",                data_type: AvpType::Grouped },
    AvpDef { code: 520,  vendor_id: TGPP, name: "Media-Type",                         data_type: AvpType::Enumerated },
    AvpDef { code: 524,  vendor_id: TGPP, name: "Codec-Data",                         data_type: AvpType::OctetString },
    AvpDef { code: 525,  vendor_id: TGPP, name: "Abort-Cause",                        data_type: AvpType::Enumerated },
    AvpDef { code: 527,  vendor_id: TGPP, name: "Service-Info-Status",                data_type: AvpType::Enumerated },
    AvpDef { code: 533,  vendor_id: TGPP, name: "Rx-Request-Type",                    data_type: AvpType::Enumerated },
    // Cx/Dx (TS 29.228/229)
    AvpDef { code: 600,  vendor_id: TGPP, name: "Visited-Network-Identifier",         data_type: AvpType::OctetString },
    AvpDef { code: 601,  vendor_id: TGPP, name: "Public-Identity",                    data_type: AvpType::UTF8String },
    AvpDef { code: 602,  vendor_id: TGPP, name: "Server-Name",                        data_type: AvpType::UTF8String },
    AvpDef { code: 603,  vendor_id: TGPP, name: "Server-Capabilities",                data_type: AvpType::Grouped },
    AvpDef { code: 604,  vendor_id: TGPP, name: "Mandatory-Capability",               data_type: AvpType::Unsigned32 },
    AvpDef { code: 605,  vendor_id: TGPP, name: "Optional-Capability",                data_type: AvpType::Unsigned32 },
    AvpDef { code: 606,  vendor_id: TGPP, name: "User-Data",                          data_type: AvpType::OctetString },
    AvpDef { code: 607,  vendor_id: TGPP, name: "SIP-Number-Auth-Items",              data_type: AvpType::Unsigned32 },
    AvpDef { code: 608,  vendor_id: TGPP, name: "SIP-Authentication-Scheme",          data_type: AvpType::UTF8String },
    AvpDef { code: 609,  vendor_id: TGPP, name: "SIP-Authenticate",                   data_type: AvpType::OctetString },
    AvpDef { code: 610,  vendor_id: TGPP, name: "SIP-Authorization",                  data_type: AvpType::OctetString },
    AvpDef { code: 611,  vendor_id: TGPP, name: "SIP-Authentication-Context",         data_type: AvpType::OctetString },
    AvpDef { code: 612,  vendor_id: TGPP, name: "SIP-Auth-Data-Item",                 data_type: AvpType::Grouped },
    AvpDef { code: 613,  vendor_id: TGPP, name: "SIP-Item-Number",                    data_type: AvpType::Unsigned32 },
    AvpDef { code: 614,  vendor_id: TGPP, name: "Server-Assignment-Type",             data_type: AvpType::Enumerated },
    AvpDef { code: 615,  vendor_id: TGPP, name: "Deregistration-Reason",              data_type: AvpType::Grouped },
    AvpDef { code: 616,  vendor_id: TGPP, name: "Reason-Code",                        data_type: AvpType::Enumerated },
    AvpDef { code: 617,  vendor_id: TGPP, name: "Reason-Info",                        data_type: AvpType::UTF8String },
    AvpDef { code: 618,  vendor_id: TGPP, name: "Charging-Information",               data_type: AvpType::Grouped },
    AvpDef { code: 619,  vendor_id: TGPP, name: "Primary-Event-Charging-Function-Name", data_type: AvpType::DiameterIdentity },
    AvpDef { code: 620,  vendor_id: TGPP, name: "Secondary-Event-Charging-Function-Name", data_type: AvpType::DiameterIdentity },
    AvpDef { code: 621,  vendor_id: TGPP, name: "Primary-Charging-Collection-Function-Name", data_type: AvpType::DiameterIdentity },
    AvpDef { code: 622,  vendor_id: TGPP, name: "Secondary-Charging-Collection-Function-Name", data_type: AvpType::DiameterIdentity },
    AvpDef { code: 623,  vendor_id: TGPP, name: "User-Authorization-Type",            data_type: AvpType::Enumerated },
    AvpDef { code: 624,  vendor_id: TGPP, name: "User-Data-Already-Available",        data_type: AvpType::Enumerated },
    AvpDef { code: 625,  vendor_id: TGPP, name: "Confidentiality-Key",                data_type: AvpType::OctetString },
    AvpDef { code: 626,  vendor_id: TGPP, name: "Integrity-Key",                      data_type: AvpType::OctetString },
    AvpDef { code: 630,  vendor_id: TGPP, name: "Feature-List-ID",                    data_type: AvpType::Unsigned32 },
    AvpDef { code: 631,  vendor_id: TGPP, name: "Feature-List",                       data_type: AvpType::Unsigned32 },
    AvpDef { code: 632,  vendor_id: TGPP, name: "Supported-Features",                 data_type: AvpType::Grouped },
    AvpDef { code: 633,  vendor_id: TGPP, name: "Associated-Identities",              data_type: AvpType::Grouped },
    AvpDef { code: 634,  vendor_id: TGPP, name: "Originating-Request",                data_type: AvpType::Enumerated },
    AvpDef { code: 641,  vendor_id: TGPP, name: "Supported-Applications",             data_type: AvpType::Grouped },
    // Sh (TS 29.329)
    AvpDef { code: 700,  vendor_id: TGPP, name: "User-Identity",                      data_type: AvpType::Grouped },
    AvpDef { code: 701,  vendor_id: TGPP, name: "Sh-MSISDN",                          data_type: AvpType::OctetString },
    AvpDef { code: 702,  vendor_id: TGPP, name: "User-Data-Sh",                       data_type: AvpType::OctetString },
    AvpDef { code: 703,  vendor_id: TGPP, name: "Data-Reference",                     data_type: AvpType::Enumerated },
    AvpDef { code: 704,  vendor_id: TGPP, name: "Service-Indication",                 data_type: AvpType::OctetString },
    AvpDef { code: 705,  vendor_id: TGPP, name: "Subs-Req-Type",                      data_type: AvpType::Enumerated },
    AvpDef { code: 706,  vendor_id: TGPP, name: "Requested-Domain",                   data_type: AvpType::Enumerated },
    AvpDef { code: 707,  vendor_id: TGPP, name: "Current-Location",                   data_type: AvpType::Enumerated },
    AvpDef { code: 708,  vendor_id: TGPP, name: "Identity-Set",                       data_type: AvpType::Enumerated },
    AvpDef { code: 709,  vendor_id: TGPP, name: "Expiry-Time",                        data_type: AvpType::Time },
    AvpDef { code: 710,  vendor_id: TGPP, name: "Send-Data-Indication",               data_type: AvpType::Enumerated },
    AvpDef { code: 711,  vendor_id: TGPP, name: "DSAI-Tag",                           data_type: AvpType::OctetString },
    // Ro/Rf Charging (TS 32.299)
    AvpDef { code: 823,  vendor_id: TGPP, name: "Event-Type",                         data_type: AvpType::Grouped },
    AvpDef { code: 824,  vendor_id: TGPP, name: "SIP-Method",                         data_type: AvpType::UTF8String },
    AvpDef { code: 825,  vendor_id: TGPP, name: "Event",                              data_type: AvpType::UTF8String },
    AvpDef { code: 829,  vendor_id: TGPP, name: "Role-of-Node",                       data_type: AvpType::Enumerated },
    AvpDef { code: 831,  vendor_id: TGPP, name: "Calling-Party-Address",              data_type: AvpType::UTF8String },
    AvpDef { code: 832,  vendor_id: TGPP, name: "Called-Party-Address",               data_type: AvpType::UTF8String },
    AvpDef { code: 833,  vendor_id: TGPP, name: "Time-Stamps",                        data_type: AvpType::Grouped },
    AvpDef { code: 834,  vendor_id: TGPP, name: "SIP-Request-Timestamp",              data_type: AvpType::Time },
    AvpDef { code: 835,  vendor_id: TGPP, name: "SIP-Response-Timestamp",             data_type: AvpType::Time },
    AvpDef { code: 838,  vendor_id: TGPP, name: "Inter-Operator-Identifier",          data_type: AvpType::Grouped },
    AvpDef { code: 839,  vendor_id: TGPP, name: "Originating-IOI",                    data_type: AvpType::UTF8String },
    AvpDef { code: 840,  vendor_id: TGPP, name: "Terminating-IOI",                    data_type: AvpType::UTF8String },
    AvpDef { code: 841,  vendor_id: TGPP, name: "IMS-Charging-Identifier",            data_type: AvpType::UTF8String },
    AvpDef { code: 848,  vendor_id: TGPP, name: "Served-Party-IP-Address",            data_type: AvpType::Address },
    AvpDef { code: 861,  vendor_id: TGPP, name: "Cause-Code",                         data_type: AvpType::Integer32 },
    AvpDef { code: 862,  vendor_id: TGPP, name: "Node-Functionality",                 data_type: AvpType::Enumerated },
    AvpDef { code: 873,  vendor_id: TGPP, name: "Service-Information",                data_type: AvpType::Grouped },
    AvpDef { code: 874,  vendor_id: TGPP, name: "PS-Information",                     data_type: AvpType::Grouped },
    AvpDef { code: 876,  vendor_id: TGPP, name: "IMS-Information",                    data_type: AvpType::Grouped },
    // Gx (TS 29.212)
    AvpDef { code: 1000, vendor_id: TGPP, name: "Bearer-Usage",                       data_type: AvpType::Enumerated },
    AvpDef { code: 1001, vendor_id: TGPP, name: "Charging-Rule-Install",              data_type: AvpType::Grouped },
    AvpDef { code: 1002, vendor_id: TGPP, name: "Charging-Rule-Remove",               data_type: AvpType::Grouped },
    AvpDef { code: 1003, vendor_id: TGPP, name: "Charging-Rule-Definition",           data_type: AvpType::Grouped },
    AvpDef { code: 1004, vendor_id: TGPP, name: "Charging-Rule-Base-Name",            data_type: AvpType::UTF8String },
    AvpDef { code: 1005, vendor_id: TGPP, name: "Charging-Rule-Name",                 data_type: AvpType::OctetString },
    AvpDef { code: 1006, vendor_id: TGPP, name: "Charging-Rule-Report",               data_type: AvpType::Grouped },
    AvpDef { code: 1007, vendor_id: TGPP, name: "Charging-Correlation-Indicator",     data_type: AvpType::Enumerated },
    AvpDef { code: 1008, vendor_id: TGPP, name: "Event-Trigger",                      data_type: AvpType::Enumerated },
    AvpDef { code: 1009, vendor_id: TGPP, name: "Metering-Method",                    data_type: AvpType::Enumerated },
    AvpDef { code: 1010, vendor_id: TGPP, name: "Offline",                            data_type: AvpType::Enumerated },
    AvpDef { code: 1011, vendor_id: TGPP, name: "Online",                             data_type: AvpType::Enumerated },
    AvpDef { code: 1012, vendor_id: TGPP, name: "Precedence",                         data_type: AvpType::Unsigned32 },
    AvpDef { code: 1013, vendor_id: TGPP, name: "Reporting-Level",                    data_type: AvpType::Enumerated },
    AvpDef { code: 1016, vendor_id: TGPP, name: "TFT-Filter",                         data_type: AvpType::OctetString },
    AvpDef { code: 1017, vendor_id: TGPP, name: "TFT-Packet-Filter-Information",      data_type: AvpType::Grouped },
    AvpDef { code: 1018, vendor_id: TGPP, name: "ToS-Traffic-Class",                  data_type: AvpType::OctetString },
    AvpDef { code: 1019, vendor_id: TGPP, name: "QoS-Information",                    data_type: AvpType::Grouped },
    AvpDef { code: 1021, vendor_id: TGPP, name: "PCC-Rule-Status",                    data_type: AvpType::Enumerated },
    AvpDef { code: 1023, vendor_id: TGPP, name: "Bearer-Identifier",                  data_type: AvpType::OctetString },
    AvpDef { code: 1024, vendor_id: TGPP, name: "Bearer-Operation",                   data_type: AvpType::Enumerated },
    AvpDef { code: 1026, vendor_id: TGPP, name: "Access-Network-Charging-Identifier-Gx", data_type: AvpType::Grouped },
    AvpDef { code: 1027, vendor_id: TGPP, name: "Bearer-Control-Mode",                data_type: AvpType::Enumerated },
    AvpDef { code: 1028, vendor_id: TGPP, name: "Network-Request-Support",            data_type: AvpType::Enumerated },
    AvpDef { code: 1030, vendor_id: TGPP, name: "Guaranteed-Bitrate-UL",              data_type: AvpType::Unsigned32 },
    AvpDef { code: 1031, vendor_id: TGPP, name: "Guaranteed-Bitrate-DL",              data_type: AvpType::Unsigned32 },
    AvpDef { code: 1032, vendor_id: TGPP, name: "IP-CAN-Type",                        data_type: AvpType::Enumerated },
    AvpDef { code: 1034, vendor_id: TGPP, name: "QoS-Negotiation",                    data_type: AvpType::Enumerated },
    AvpDef { code: 1035, vendor_id: TGPP, name: "QoS-Upgrade",                        data_type: AvpType::Enumerated },
    AvpDef { code: 1040, vendor_id: TGPP, name: "Default-EPS-Bearer-QoS",             data_type: AvpType::Grouped },
    AvpDef { code: 1045, vendor_id: TGPP, name: "AN-GW-Address",                      data_type: AvpType::Address },
    AvpDef { code: 1046, vendor_id: TGPP, name: "Resource-Allocation-Notification",   data_type: AvpType::Enumerated },
    AvpDef { code: 1047, vendor_id: TGPP, name: "Security-Parameter-Index",           data_type: AvpType::OctetString },
    AvpDef { code: 1048, vendor_id: TGPP, name: "Flow-Label",                         data_type: AvpType::OctetString },
    AvpDef { code: 1050, vendor_id: TGPP, name: "Flow-Information",                   data_type: AvpType::Grouped },
    AvpDef { code: 1055, vendor_id: TGPP, name: "Packet-Filter-Content",              data_type: AvpType::OctetString },
    AvpDef { code: 1056, vendor_id: TGPP, name: "Packet-Filter-Identifier",           data_type: AvpType::OctetString },
    AvpDef { code: 1057, vendor_id: TGPP, name: "Packet-Filter-Information",          data_type: AvpType::Grouped },
    AvpDef { code: 1058, vendor_id: TGPP, name: "Packet-Filter-Operation",            data_type: AvpType::Enumerated },
    AvpDef { code: 1062, vendor_id: TGPP, name: "Usage-Monitoring-Information",       data_type: AvpType::Grouped },
    AvpDef { code: 1063, vendor_id: TGPP, name: "Usage-Monitoring-Level",             data_type: AvpType::Enumerated },
    AvpDef { code: 1064, vendor_id: TGPP, name: "Usage-Monitoring-Report",            data_type: AvpType::Enumerated },
    AvpDef { code: 1065, vendor_id: TGPP, name: "Usage-Monitoring-Support",           data_type: AvpType::Enumerated },
    // S6a (TS 29.272) — Authentication + Subscription Data
    AvpDef { code: 1400, vendor_id: TGPP, name: "Subscription-Data",                  data_type: AvpType::Grouped },
    AvpDef { code: 1401, vendor_id: TGPP, name: "Terminal-Information",               data_type: AvpType::Grouped },
    AvpDef { code: 1402, vendor_id: TGPP, name: "IMEI",                               data_type: AvpType::UTF8String },
    AvpDef { code: 1403, vendor_id: TGPP, name: "Software-Version",                   data_type: AvpType::UTF8String },
    AvpDef { code: 1404, vendor_id: TGPP, name: "QoS-Subscribed",                     data_type: AvpType::OctetString },
    AvpDef { code: 1405, vendor_id: TGPP, name: "ULR-Flags",                          data_type: AvpType::Unsigned32 },
    AvpDef { code: 1406, vendor_id: TGPP, name: "ULA-Flags",                          data_type: AvpType::Unsigned32 },
    AvpDef { code: 1407, vendor_id: TGPP, name: "Visited-PLMN-Id",                    data_type: AvpType::OctetString },
    AvpDef { code: 1408, vendor_id: TGPP, name: "Requested-EUTRAN-Authentication-Info", data_type: AvpType::Grouped },
    AvpDef { code: 1409, vendor_id: TGPP, name: "Requested-UTRAN-GERAN-Authentication-Info", data_type: AvpType::Grouped },
    AvpDef { code: 1410, vendor_id: TGPP, name: "Number-Of-Requested-Vectors",        data_type: AvpType::Unsigned32 },
    AvpDef { code: 1411, vendor_id: TGPP, name: "Re-Synchronization-Info",            data_type: AvpType::OctetString },
    AvpDef { code: 1412, vendor_id: TGPP, name: "Immediate-Response-Preferred",       data_type: AvpType::Unsigned32 },
    AvpDef { code: 1413, vendor_id: TGPP, name: "Authentication-Info",                data_type: AvpType::Grouped },
    AvpDef { code: 1414, vendor_id: TGPP, name: "E-UTRAN-Vector",                     data_type: AvpType::Grouped },
    AvpDef { code: 1415, vendor_id: TGPP, name: "UTRAN-Vector",                       data_type: AvpType::Grouped },
    AvpDef { code: 1416, vendor_id: TGPP, name: "GERAN-Vector",                       data_type: AvpType::Grouped },
    AvpDef { code: 1419, vendor_id: TGPP, name: "RAND",                               data_type: AvpType::OctetString },
    AvpDef { code: 1420, vendor_id: TGPP, name: "XRES",                               data_type: AvpType::OctetString },
    AvpDef { code: 1421, vendor_id: TGPP, name: "AUTN",                               data_type: AvpType::OctetString },
    AvpDef { code: 1422, vendor_id: TGPP, name: "KASME",                              data_type: AvpType::OctetString },
    AvpDef { code: 1424, vendor_id: TGPP, name: "Item-Number",                        data_type: AvpType::Unsigned32 },
    AvpDef { code: 1426, vendor_id: TGPP, name: "Context-Identifier",                 data_type: AvpType::Unsigned32 },
    AvpDef { code: 1428, vendor_id: TGPP, name: "Subscriber-Status",                  data_type: AvpType::Enumerated },
    AvpDef { code: 1429, vendor_id: TGPP, name: "Operator-Determined-Barring",        data_type: AvpType::Unsigned32 },
    AvpDef { code: 1430, vendor_id: TGPP, name: "Access-Restriction-Data",            data_type: AvpType::Unsigned32 },
    AvpDef { code: 1431, vendor_id: TGPP, name: "APN-OI-Replacement",                 data_type: AvpType::UTF8String },
    AvpDef { code: 1432, vendor_id: TGPP, name: "All-APN-Configurations-Included-Indicator", data_type: AvpType::Enumerated },
    AvpDef { code: 1433, vendor_id: TGPP, name: "APN-Configuration-Profile",          data_type: AvpType::Grouped },
    AvpDef { code: 1434, vendor_id: TGPP, name: "APN-Configuration",                  data_type: AvpType::Grouped },
    AvpDef { code: 1435, vendor_id: TGPP, name: "EPS-Subscribed-QoS-Profile",         data_type: AvpType::Grouped },
    AvpDef { code: 1436, vendor_id: TGPP, name: "VPLMN-Dynamic-Address-Allowed",      data_type: AvpType::Enumerated },
    AvpDef { code: 1437, vendor_id: TGPP, name: "STN-SR",                             data_type: AvpType::OctetString },
    AvpDef { code: 1440, vendor_id: TGPP, name: "DSR-Flags",                          data_type: AvpType::Unsigned32 },
    AvpDef { code: 1441, vendor_id: TGPP, name: "DSA-Flags",                          data_type: AvpType::Unsigned32 },
    AvpDef { code: 1442, vendor_id: TGPP, name: "IDA-Flags",                          data_type: AvpType::Unsigned32 },
    AvpDef { code: 1443, vendor_id: TGPP, name: "PUA-Flags",                          data_type: AvpType::Unsigned32 },
    AvpDef { code: 1444, vendor_id: TGPP, name: "NOR-Flags",                          data_type: AvpType::Unsigned32 },
    AvpDef { code: 1445, vendor_id: TGPP, name: "IMS-Voice-Over-PS-Sessions-Supported", data_type: AvpType::Enumerated },
    AvpDef { code: 1446, vendor_id: TGPP, name: "Homogeneous-Support-of-IMS-Voice-Over-PS-Sessions", data_type: AvpType::Enumerated },
    AvpDef { code: 1447, vendor_id: TGPP, name: "Last-UE-Activity-Time",              data_type: AvpType::Time },
    AvpDef { code: 1448, vendor_id: TGPP, name: "EPS-User-State",                     data_type: AvpType::Grouped },
    AvpDef { code: 1449, vendor_id: TGPP, name: "EPS-Location-Information",           data_type: AvpType::Grouped },
    AvpDef { code: 1450, vendor_id: TGPP, name: "MME-User-State",                     data_type: AvpType::Grouped },
    AvpDef { code: 1451, vendor_id: TGPP, name: "SGSN-User-State",                    data_type: AvpType::Grouped },
    AvpDef { code: 1452, vendor_id: TGPP, name: "User-State",                         data_type: AvpType::Enumerated },
    AvpDef { code: 1453, vendor_id: TGPP, name: "MME-Location-Information",           data_type: AvpType::Grouped },
    AvpDef { code: 1454, vendor_id: TGPP, name: "SGSN-Location-Information",          data_type: AvpType::Grouped },
    AvpDef { code: 1455, vendor_id: TGPP, name: "E-UTRAN-Cell-Global-Identity",       data_type: AvpType::OctetString },
    AvpDef { code: 1456, vendor_id: TGPP, name: "Tracking-Area-Identity",             data_type: AvpType::OctetString },
    AvpDef { code: 1457, vendor_id: TGPP, name: "Cell-Global-Identity",               data_type: AvpType::OctetString },
    AvpDef { code: 1458, vendor_id: TGPP, name: "Routing-Area-Identity",              data_type: AvpType::OctetString },
    AvpDef { code: 1459, vendor_id: TGPP, name: "Location-Area-Identity",             data_type: AvpType::OctetString },
    AvpDef { code: 1460, vendor_id: TGPP, name: "Service-Area-Identity",              data_type: AvpType::OctetString },
    AvpDef { code: 1461, vendor_id: TGPP, name: "Geographical-Information",           data_type: AvpType::OctetString },
    AvpDef { code: 1462, vendor_id: TGPP, name: "Geodetic-Information",               data_type: AvpType::OctetString },
    AvpDef { code: 1463, vendor_id: TGPP, name: "Current-Location-Retrieved",         data_type: AvpType::Enumerated },
    AvpDef { code: 1464, vendor_id: TGPP, name: "Age-Of-Location-Information",        data_type: AvpType::Unsigned32 },
    AvpDef { code: 1470, vendor_id: TGPP, name: "MSISDN",                             data_type: AvpType::OctetString },
    AvpDef { code: 1472, vendor_id: TGPP, name: "PDN-Type",                           data_type: AvpType::Enumerated },
    AvpDef { code: 1474, vendor_id: TGPP, name: "AMBR",                               data_type: AvpType::Grouped },
    AvpDef { code: 1490, vendor_id: TGPP, name: "CLR-Flags",                          data_type: AvpType::Unsigned32 },
    AvpDef { code: 1491, vendor_id: TGPP, name: "Cancellation-Type",                  data_type: AvpType::Enumerated },
    AvpDef { code: 1515, vendor_id: TGPP, name: "Max-Requested-Bandwidth-UL",         data_type: AvpType::Unsigned32 },
    AvpDef { code: 1516, vendor_id: TGPP, name: "Max-Requested-Bandwidth-DL",         data_type: AvpType::Unsigned32 },
    AvpDef { code: 1520, vendor_id: TGPP, name: "QoS-Class-Identifier",               data_type: AvpType::Enumerated },
    AvpDef { code: 1521, vendor_id: TGPP, name: "Priority-Level",                     data_type: AvpType::Unsigned32 },
    AvpDef { code: 1522, vendor_id: TGPP, name: "Pre-emption-Capability",             data_type: AvpType::Enumerated },
    AvpDef { code: 1523, vendor_id: TGPP, name: "Pre-emption-Vulnerability",          data_type: AvpType::Enumerated },
    AvpDef { code: 1524, vendor_id: TGPP, name: "Allocation-Retention-Priority",      data_type: AvpType::Grouped },
    // Gy (TS 32.299)
    AvpDef { code: 2006, vendor_id: TGPP, name: "Multiple-Services-Credit-Control",   data_type: AvpType::Grouped },
];

/// Look up an AVP definition by (code, vendor_id).
///
/// Uses binary search on the static table (sorted by vendor_id, then code).
pub fn lookup_avp(code: u32, vendor_id: u32) -> Option<&'static AvpDef> {
    AVP_TABLE
        .binary_search_by(|entry| {
            entry.vendor_id.cmp(&vendor_id).then(entry.code.cmp(&code))
        })
        .ok()
        .map(|idx| &AVP_TABLE[idx])
}

/// Look up an AVP definition by name (linear scan — use sparingly).
pub fn lookup_by_name(name: &str) -> Option<&'static AvpDef> {
    AVP_TABLE.iter().find(|entry| entry.name == name)
}

/// Look up an AVP name by code (tries vendor=0, then vendor=10415).
pub fn avp_name(code: u32) -> Option<&'static str> {
    lookup_avp(code, 0)
        .or_else(|| lookup_avp(code, VENDOR_3GPP))
        .map(|def| def.name)
}

/// Total number of AVP definitions in the dictionary.
pub fn avp_count() -> usize {
    AVP_TABLE.len()
}

// ── Application IDs ──────────────────────────────────────────────────────

/// Cx Application-Id (TS 29.228/29.229) — IMS registration/auth
pub const CX_APP_ID: u32 = 16777216;
/// Sh Application-Id (TS 29.328/29.329) — IMS user data
pub const SH_APP_ID: u32 = 16777217;
/// Gx Application-Id (TS 29.212) — Policy and Charging Control
pub const GX_APP_ID: u32 = 16777238;
/// Rx Application-Id (TS 29.214) — QoS/policy (P-CSCF ↔ PCRF/PCF)
pub const RX_APP_ID: u32 = 16777236;
/// S6a Application-Id (TS 29.272)
pub const S6A_APP_ID: u32 = 16777251;
/// S13 Application-Id (TS 29.272) — EIR (same app_id as S6a, different cmd)
pub const S13_APP_ID: u32 = 16777252;
/// Ro Application-Id (RFC 4006 / TS 32.299) — Online Charging
pub const RO_APP_ID: u32 = 4;
/// Rf Application-Id (TS 32.299) — Offline Charging (base accounting)
pub const RF_APP_ID: u32 = 3;
/// 3GPP Vendor-Id
pub const VENDOR_3GPP: u32 = 10415;

// ── S6a Command Codes (TS 29.272) ────────────────────────────────────────

/// Update-Location-Request/Answer
pub const CMD_UPDATE_LOCATION: u32 = 316;
/// Cancel-Location-Request/Answer
pub const CMD_CANCEL_LOCATION: u32 = 317;
/// Authentication-Information-Request/Answer
pub const CMD_AUTHENTICATION_INFORMATION: u32 = 318;
/// Insert-Subscriber-Data-Request/Answer
pub const CMD_INSERT_SUBSCRIBER_DATA: u32 = 319;
/// Delete-Subscriber-Data-Request/Answer
pub const CMD_DELETE_SUBSCRIBER_DATA: u32 = 320;
/// Purge-UE-Request/Answer
pub const CMD_PURGE_UE: u32 = 321;
/// Notify-Request/Answer
pub const CMD_NOTIFY: u32 = 323;

// ── S13 Command Code (TS 29.272) ────────────────────────────────────────

/// ME-Identity-Check-Request/Answer (EIR)
pub const CMD_ME_IDENTITY_CHECK: u32 = 324;

// ── Cx/Dx Command Codes (TS 29.228) ────────────────────────────────────

/// User-Authorization-Request/Answer
pub const CMD_USER_AUTHORIZATION: u32 = 300;
/// Server-Assignment-Request/Answer
pub const CMD_SERVER_ASSIGNMENT: u32 = 301;
/// Location-Info-Request/Answer
pub const CMD_LOCATION_INFO: u32 = 302;
/// Multimedia-Auth-Request/Answer
pub const CMD_MULTIMEDIA_AUTH: u32 = 303;
/// Registration-Termination-Request/Answer
pub const CMD_REGISTRATION_TERMINATION: u32 = 304;
/// Push-Profile-Request/Answer
pub const CMD_PUSH_PROFILE: u32 = 305;

// ── Sh Command Codes (TS 29.329) ────────────────────────────────────────

/// User-Data-Request/Answer (Sh)
pub const CMD_SH_USER_DATA: u32 = 306;
/// Profile-Update-Request/Answer (Sh)
pub const CMD_SH_PROFILE_UPDATE: u32 = 307;
/// Subscribe-Notifications-Request/Answer (Sh)
pub const CMD_SH_SUBSCRIBE_NOTIFICATIONS: u32 = 308;
/// Push-Notification-Request/Answer (Sh)
pub const CMD_SH_PUSH_NOTIFICATION: u32 = 309;

// ── Gx Command Codes (TS 29.212) ────────────────────────────────────────

/// Credit-Control-Request/Answer (Gx uses 272, same as Gy)
pub const CMD_CREDIT_CONTROL: u32 = 272;
/// Re-Auth-Request/Answer (Gx RAR: PCRF → PGW)
pub const CMD_RE_AUTH: u32 = 258;
/// Abort-Session-Request/Answer
pub const CMD_ABORT_SESSION: u32 = 274;

// ── Rx Command Codes (TS 29.214) ────────────────────────────────────────

/// AA-Request/Answer (Rx: P-CSCF → PCRF)
pub const CMD_AA: u32 = 265;
/// Session-Termination-Request/Answer (Rx)
pub const CMD_SESSION_TERMINATION: u32 = 275;

// ── Ro/Rf Command Codes (TS 32.299) ──────────────────────────────────

/// Accounting-Request/Answer (Rf offline charging)
pub const CMD_ACCOUNTING: u32 = 271;

// ── Base Diameter Command Codes ──────────────────────────────────────────

pub const CMD_CAPABILITIES_EXCHANGE: u32 = 257;
pub const CMD_DEVICE_WATCHDOG: u32 = 280;
pub const CMD_DISCONNECT_PEER: u32 = 282;

// ── Result Codes ─────────────────────────────────────────────────────────

pub const DIAMETER_SUCCESS: u32 = 2001;
pub const DIAMETER_LIMITED_SUCCESS: u32 = 2002;
pub const DIAMETER_UNABLE_TO_DELIVER: u32 = 3002;
pub const DIAMETER_LOOP_DETECTED: u32 = 3005;
pub const DIAMETER_UNABLE_TO_COMPLY: u32 = 5012;
pub const DIAMETER_ERROR_USER_UNKNOWN: u32 = 5001;
pub const DIAMETER_ERROR_ABSENT_USER: u32 = 4201;

// ── 3GPP Experimental Result Codes ──────────────────────────────────────

/// S6a: subscriber not found
pub const DIAMETER_ERROR_USER_UNKNOWN_3GPP: u32 = 5001;
/// S6a: unknown EPS subscription
pub const DIAMETER_ERROR_UNKNOWN_EPS_SUBSCRIPTION: u32 = 5420;
/// S6a: RAT not allowed
pub const DIAMETER_ERROR_RAT_NOT_ALLOWED: u32 = 5421;
/// S6a: roaming not allowed
pub const DIAMETER_ERROR_ROAMING_NOT_ALLOWED: u32 = 5004;
/// Cx: first registration
pub const DIAMETER_FIRST_REGISTRATION: u32 = 2001;
/// Cx: subsequent registration
pub const DIAMETER_SUBSEQUENT_REGISTRATION: u32 = 2002;
/// Cx: server name not stored
pub const DIAMETER_SERVER_NAME_NOT_STORED: u32 = 2003;
/// Cx: identity not registered
pub const DIAMETER_ERROR_IDENTITY_NOT_REGISTERED: u32 = 5003;
/// S13: equipment unknown
pub const DIAMETER_ERROR_EQUIPMENT_UNKNOWN: u32 = 5422;

// ── Cancellation Types (S6a) ─────────────────────────────────────────────

pub const CANCELLATION_TYPE_MME_UPDATE_PROCEDURE: u32 = 0;
pub const CANCELLATION_TYPE_SGSN_UPDATE_PROCEDURE: u32 = 1;
pub const CANCELLATION_TYPE_SUBSCRIPTION_WITHDRAWAL: u32 = 2;
pub const CANCELLATION_TYPE_INITIAL_ATTACH_PROCEDURE: u32 = 4;

// ── AVP Codes (for encoding) ─────────────────────────────────────────────

pub mod avp {
    // Base Diameter
    pub const USER_NAME: u32 = 1;
    pub const HOST_IP_ADDRESS: u32 = 257;
    pub const AUTH_APPLICATION_ID: u32 = 258;
    pub const VENDOR_SPECIFIC_APPLICATION_ID: u32 = 260;
    pub const SESSION_ID: u32 = 263;
    pub const ORIGIN_HOST: u32 = 264;
    pub const SUPPORTED_VENDOR_ID: u32 = 265;
    pub const VENDOR_ID: u32 = 266;
    pub const FIRMWARE_REVISION: u32 = 267;
    pub const RESULT_CODE: u32 = 268;
    pub const PRODUCT_NAME: u32 = 269;
    pub const AUTH_SESSION_STATE: u32 = 277;
    pub const ORIGIN_STATE_ID: u32 = 278;
    pub const ROUTE_RECORD: u32 = 282;
    pub const DESTINATION_REALM: u32 = 283;
    pub const DESTINATION_HOST: u32 = 293;
    pub const ORIGIN_REALM: u32 = 296;
    pub const EXPERIMENTAL_RESULT: u32 = 297;
    pub const EXPERIMENTAL_RESULT_CODE: u32 = 298;

    // Base RADIUS/Diameter
    pub const FRAMED_IP_ADDRESS: u32 = 8;
    pub const FRAMED_IPV6_PREFIX: u32 = 97;
    pub const ACCT_APPLICATION_ID: u32 = 259;

    // Accounting (RFC 6733)
    pub const ACCOUNTING_RECORD_TYPE: u32 = 480;
    pub const ACCOUNTING_RECORD_NUMBER: u32 = 485;

    // RFC 4006 Credit-Control (Gy)
    pub const CC_REQUEST_TYPE: u32 = 415;
    pub const CC_REQUEST_NUMBER: u32 = 416;
    pub const GRANTED_SERVICE_UNIT: u32 = 426;
    pub const RATING_GROUP: u32 = 427;
    pub const FINAL_UNIT_INDICATION: u32 = 431;
    pub const FINAL_UNIT_ACTION: u32 = 432;
    pub const REQUESTED_SERVICE_UNIT: u32 = 437;
    pub const SUBSCRIPTION_ID: u32 = 443;
    pub const SUBSCRIPTION_ID_DATA: u32 = 444;
    pub const SUBSCRIPTION_ID_TYPE: u32 = 450;
    pub const CC_TIME: u32 = 454;
    pub const CC_TOTAL_OCTETS: u32 = 456;
    pub const CC_INPUT_OCTETS: u32 = 457;
    pub const CC_OUTPUT_OCTETS: u32 = 458;
    pub const SERVICE_IDENTIFIER: u32 = 461;
    pub const USED_SERVICE_UNIT: u32 = 446;
    pub const VALIDITY_TIME: u32 = 448;

    // 3GPP S6a (TS 29.272)
    pub const SERVICE_SELECTION: u32 = 493;
    pub const SUBSCRIPTION_DATA: u32 = 1400;
    pub const TERMINAL_INFORMATION: u32 = 1401;
    pub const IMEI: u32 = 1402;
    pub const SOFTWARE_VERSION: u32 = 1403;
    pub const ULR_FLAGS: u32 = 1405;
    pub const ULA_FLAGS: u32 = 1406;
    pub const VISITED_PLMN_ID: u32 = 1407;
    pub const REQUESTED_EUTRAN_AUTH_INFO: u32 = 1408;
    pub const REQUESTED_UTRAN_GERAN_AUTH_INFO: u32 = 1409;
    pub const NUMBER_OF_REQUESTED_VECTORS: u32 = 1410;
    pub const RE_SYNCHRONIZATION_INFO: u32 = 1411;
    pub const IMMEDIATE_RESPONSE_PREFERRED: u32 = 1412;
    pub const AUTHENTICATION_INFO: u32 = 1413;
    pub const E_UTRAN_VECTOR: u32 = 1414;
    pub const UTRAN_VECTOR: u32 = 1415;
    pub const GERAN_VECTOR: u32 = 1416;
    pub const RAND: u32 = 1419;
    pub const XRES: u32 = 1420;
    pub const AUTN: u32 = 1421;
    pub const KASME: u32 = 1422;
    pub const ITEM_NUMBER: u32 = 1424;
    pub const CONTEXT_IDENTIFIER: u32 = 1426;
    pub const SUBSCRIBER_STATUS: u32 = 1428;
    pub const OPERATOR_DETERMINED_BARRING: u32 = 1429;
    pub const ACCESS_RESTRICTION_DATA: u32 = 1430;
    pub const ALL_APN_CONFIGURATIONS_INCLUDED_INDICATOR: u32 = 1432;
    pub const APN_CONFIGURATION_PROFILE: u32 = 1433;
    pub const APN_CONFIGURATION: u32 = 1434;
    pub const EPS_SUBSCRIBED_QOS_PROFILE: u32 = 1435;
    pub const VPLMN_DYNAMIC_ADDRESS_ALLOWED: u32 = 1436;
    pub const CLR_FLAGS: u32 = 1490;
    pub const CANCELLATION_TYPE: u32 = 1491;
    pub const MSISDN: u32 = 1470;
    pub const PDN_TYPE: u32 = 1472;
    pub const AMBR: u32 = 1474;
    pub const MAX_REQUESTED_BANDWIDTH_UL: u32 = 1515;
    pub const MAX_REQUESTED_BANDWIDTH_DL: u32 = 1516;
    pub const QOS_CLASS_IDENTIFIER: u32 = 1520;
    pub const PRIORITY_LEVEL: u32 = 1521;
    pub const PRE_EMPTION_CAPABILITY: u32 = 1522;
    pub const PRE_EMPTION_VULNERABILITY: u32 = 1523;
    pub const ALLOCATION_RETENTION_PRIORITY: u32 = 1524;

    // 3GPP Cx (TS 29.228)
    pub const VISITED_NETWORK_IDENTIFIER: u32 = 600;
    pub const PUBLIC_IDENTITY: u32 = 601;
    pub const SERVER_NAME: u32 = 602;
    pub const SERVER_CAPABILITIES: u32 = 603;
    pub const MANDATORY_CAPABILITY: u32 = 604;
    pub const OPTIONAL_CAPABILITY: u32 = 605;
    pub const USER_DATA_CX: u32 = 606;
    pub const SIP_NUMBER_AUTH_ITEMS: u32 = 607;
    pub const SIP_AUTHENTICATION_SCHEME: u32 = 608;
    pub const SIP_AUTHENTICATE: u32 = 609;
    pub const SIP_AUTHORIZATION: u32 = 610;
    pub const SIP_AUTH_DATA_ITEM: u32 = 612;
    pub const SERVER_ASSIGNMENT_TYPE: u32 = 614;
    pub const DEREGISTRATION_REASON: u32 = 615;
    pub const REASON_CODE: u32 = 616;
    pub const REASON_INFO: u32 = 617;
    pub const CHARGING_INFORMATION: u32 = 618;
    pub const USER_AUTHORIZATION_TYPE: u32 = 623;
    pub const USER_DATA_ALREADY_AVAILABLE: u32 = 624;
    pub const CONFIDENTIALITY_KEY: u32 = 625;
    pub const INTEGRITY_KEY: u32 = 626;
    pub const FEATURE_LIST_ID: u32 = 630;
    pub const FEATURE_LIST: u32 = 631;
    pub const SUPPORTED_FEATURES: u32 = 632;

    // 3GPP Sh (TS 29.329)
    pub const USER_IDENTITY: u32 = 700;
    pub const USER_DATA_SH: u32 = 702;
    pub const DATA_REFERENCE: u32 = 703;
    pub const SERVICE_INDICATION: u32 = 704;
    pub const SUBS_REQ_TYPE: u32 = 705;

    // 3GPP Gx (TS 29.212)
    pub const CHARGING_RULE_INSTALL: u32 = 1001;
    pub const CHARGING_RULE_REMOVE: u32 = 1002;
    pub const CHARGING_RULE_DEFINITION: u32 = 1003;
    pub const CHARGING_RULE_BASE_NAME: u32 = 1004;
    pub const CHARGING_RULE_NAME: u32 = 1005;
    pub const EVENT_TRIGGER: u32 = 1008;
    pub const METERING_METHOD: u32 = 1009;
    pub const OFFLINE: u32 = 1010;
    pub const ONLINE: u32 = 1011;
    pub const PRECEDENCE: u32 = 1012;
    pub const QOS_INFORMATION: u32 = 1019;
    pub const BEARER_IDENTIFIER: u32 = 1023;
    pub const DEFAULT_EPS_BEARER_QOS: u32 = 1040;
    pub const GUARANTEED_BITRATE_UL: u32 = 1030;
    pub const GUARANTEED_BITRATE_DL: u32 = 1031;
    pub const IP_CAN_TYPE: u32 = 1032;
    pub const FLOW_INFORMATION: u32 = 1050;

    // 3GPP Rx (TS 29.214)
    pub const ACCESS_NETWORK_CHARGING_ADDRESS: u32 = 501;
    pub const ACCESS_NETWORK_CHARGING_IDENTIFIER: u32 = 502;
    pub const AF_APPLICATION_IDENTIFIER: u32 = 504;
    pub const AF_CHARGING_IDENTIFIER: u32 = 505;
    pub const FLOW_DESCRIPTION: u32 = 507;
    pub const FLOW_NUMBER: u32 = 508;
    pub const FLOW_STATUS: u32 = 510;
    pub const MEDIA_COMPONENT_DESCRIPTION: u32 = 515;
    pub const MEDIA_COMPONENT_NUMBER: u32 = 517;
    pub const MEDIA_SUB_COMPONENT: u32 = 518;
    pub const MEDIA_TYPE: u32 = 520;
    pub const ABORT_CAUSE: u32 = 525;
    pub const SPECIFIC_ACTION: u32 = 512;
    pub const CODEC_DATA: u32 = 524;
    pub const SERVICE_INFO_STATUS: u32 = 527;
    pub const RX_REQUEST_TYPE: u32 = 533;
    pub const FLOWS: u32 = 509;
    pub const FLOW_USAGE: u32 = 511;

    // 3GPP Ro/Rf Charging (TS 32.299)
    pub const EVENT_TYPE: u32 = 823;
    pub const SIP_METHOD_CHARGING: u32 = 824;
    pub const EVENT: u32 = 825;
    pub const ROLE_OF_NODE: u32 = 829;
    pub const CALLING_PARTY_ADDRESS: u32 = 831;
    pub const CALLED_PARTY_ADDRESS: u32 = 832;
    pub const TIME_STAMPS: u32 = 833;
    pub const SIP_REQUEST_TIMESTAMP: u32 = 834;
    pub const SIP_RESPONSE_TIMESTAMP: u32 = 835;
    pub const INTER_OPERATOR_IDENTIFIER: u32 = 838;
    pub const ORIGINATING_IOI: u32 = 839;
    pub const TERMINATING_IOI: u32 = 840;
    pub const IMS_CHARGING_IDENTIFIER: u32 = 841;
    pub const SERVED_PARTY_IP_ADDRESS: u32 = 848;
    pub const CAUSE_CODE: u32 = 861;
    pub const NODE_FUNCTIONALITY: u32 = 862;
    pub const SERVICE_INFORMATION: u32 = 873;
    pub const IMS_INFORMATION: u32 = 876;

    // 3GPP Gy (TS 32.299)
    pub const MULTIPLE_SERVICES_CREDIT_CONTROL: u32 = 2006;

}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_ordering_is_valid() {
        for pair in AVP_TABLE.windows(2) {
            let left = (pair[0].vendor_id, pair[0].code);
            let right = (pair[1].vendor_id, pair[1].code);
            assert!(
                left < right,
                "table not sorted at {} (v={}) vs {} (v={})",
                pair[0].name, pair[0].vendor_id,
                pair[1].name, pair[1].vendor_id,
            );
        }
    }

    #[test]
    fn base_diameter_session_id() {
        let entry = lookup_avp(263, 0).unwrap();
        assert_eq!(entry.name, "Session-Id");
        assert!(entry.data_type.is_text());
        assert!(!entry.is_vendor_specific());
    }

    #[test]
    fn base_diameter_result_code() {
        let entry = lookup_avp(268, 0).unwrap();
        assert_eq!(entry.name, "Result-Code");
        assert_eq!(entry.data_type, AvpType::Unsigned32);
    }

    #[test]
    fn vendor_specific_cx_server_name() {
        let entry = lookup_avp(602, TGPP).unwrap();
        assert_eq!(entry.name, "Server-Name");
        assert!(entry.is_vendor_specific());
        assert!(entry.data_type.is_text());
    }

    #[test]
    fn grouped_avps_are_containers() {
        let auth_info = lookup_avp(1413, TGPP).unwrap();
        assert_eq!(auth_info.name, "Authentication-Info");
        assert!(auth_info.data_type.is_container());
    }

    #[test]
    fn unknown_code_returns_none() {
        assert!(lookup_avp(65535, 0).is_none());
        assert!(lookup_avp(1, 99999).is_none());
    }

    #[test]
    fn lookup_by_name_finds_entries() {
        let entry = lookup_by_name("Origin-Host").unwrap();
        assert_eq!(entry.code, 264);
        assert_eq!(entry.vendor_id, 0);

        let entry = lookup_by_name("Public-Identity").unwrap();
        assert_eq!(entry.code, 601);
        assert_eq!(entry.vendor_id, TGPP);

        assert!(lookup_by_name("Nonexistent-AVP").is_none());
    }

    #[test]
    fn avp_count_is_substantial() {
        assert!(avp_count() > 200, "dictionary should have > 200 AVP entries");
    }

    #[test]
    fn avp_type_classification() {
        assert!(AvpType::Grouped.is_container());
        assert!(!AvpType::Unsigned32.is_container());
        assert!(AvpType::UTF8String.is_text());
        assert!(AvpType::DiameterIdentity.is_text());
        assert!(!AvpType::OctetString.is_text());
    }
}
