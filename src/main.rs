// SPDX-License-Identifier: AGPL-3.0-only

use std::env;

use const_oid::db::rfc5280::ID_CE_CRL_REASONS;
use const_oid::db::DB;
use const_oid::ObjectIdentifier;
use der::{Decode, Sequence};
use x509::attr::Attribute;
use x509::crl::{CertificateList, RevokedCert};
use x509::ext::pkix::name::{DistributionPointName, GeneralName};
use x509::ext::pkix::{CrlDistributionPoints, CrlReason};
use x509::request::{CertReq, ExtensionReq};
use x509::{Certificate, TbsCertificate};

#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct CrlPair<'a> {
    pub url: String,
    pub crl: CertificateList<'a>,
}

#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct CachedCrl<'a> {
    pub crls: Vec<CrlPair<'a>>,
}

fn oid_name(oid: &ObjectIdentifier) -> String {
    match DB.resolve(&oid.to_string()) {
        Ok(name) => String::from(name),
        Err(_) => oid.to_string(),
    }
}

fn crl_reason(revoked: &RevokedCert) -> String {
    if let Some(exts) = &revoked.crl_entry_extensions {
        for ext in exts {
            if ext.extn_id == ID_CE_CRL_REASONS {
                return match CrlReason::from_der(ext.extn_value).unwrap() {
                    CrlReason::Unspecified => "Unspecified",
                    CrlReason::KeyCompromise => "Key compromise",
                    CrlReason::CaCompromise => "CA compromise",
                    CrlReason::AffiliationChanged => "Affiliation changed",
                    CrlReason::Superseded => "Superseded",
                    CrlReason::CessationOfOperation => "Cessation of operation",
                    CrlReason::CertificateHold => "Certificate hold",
                    CrlReason::RemoveFromCRL => "Remove from CRL",
                    CrlReason::PrivilegeWithdrawn => "Privilege withdrawn",
                    CrlReason::AaCompromise => "AA compromise",
                }
                .to_string();
            }
        }
    }
    "Unknown".into()
}

fn crl_urls(cert: &TbsCertificate) -> Vec<String> {
    const CRL_EXTN: ObjectIdentifier = const_oid::db::rfc5912::ID_CE_CRL_DISTRIBUTION_POINTS;
    let mut urls_vec: Vec<String> = Vec::new();

    if let Some(extensions) = cert.extensions.as_ref() {
        for ext in extensions.iter() {
            if ext.extn_id == CRL_EXTN {
                let urls = CrlDistributionPoints::from_der(ext.extn_value).unwrap();
                for url in urls.0 {
                    if let Some(dist_pt) = url.distribution_point {
                        match dist_pt {
                            DistributionPointName::FullName(names) => {
                                for name in names {
                                    match name {
                                        GeneralName::UniformResourceIdentifier(uri) => {
                                            urls_vec.push(uri.to_string());
                                        }
                                        x => {
                                            eprintln!("unsupported {:?}", x);
                                        }
                                    }
                                }
                            }
                            x => {
                                eprintln!("unsupported {:?}", x);
                            }
                        }
                    }
                }
            }
        }
    }

    urls_vec
}

fn print_crl(crl: &CertificateList) {
    println!("Issuer: {}", crl.tbs_cert_list.issuer);
    println!("Signing Algo: {}", oid_name(&crl.signature_algorithm.oid));

    println!("This update: {}", crl.tbs_cert_list.this_update);
    if let Some(next_update) = crl.tbs_cert_list.next_update {
        println!("Next update: {}", next_update);
    }

    if let Some(revoked) = &crl.tbs_cert_list.revoked_certificates {
        println!("Certificates revoked: {}", revoked.len());
        let revoked_serials: Vec<String> = revoked
            .iter()
            .map(|r| {
                format!(
                    "{}: {}",
                    hex::encode(r.serial_number.as_bytes()),
                    crl_reason(r)
                )
            })
            .collect();
        println!("{}", revoked_serials.join("\n"));
    } else {
        println!("No revoked certificates.");
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <path to DER file>", args[0]);
        std::process::exit(10);
    }
    for arg in &args[1..] {
        let contents = match std::fs::read(arg) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("Failed to read {}: {}", arg, e);
                continue;
            }
        };

        if let Ok(cert) = Certificate::from_der(&contents) {
            println!("{} decoded as a Certificate", arg);
            println!("Issuer: {}", cert.tbs_certificate.issuer);
            if let Some(issuer_id) = cert.tbs_certificate.issuer_unique_id {
                println!("\tID: {:?}", issuer_id);
            }
            println!("Subject: {}", cert.tbs_certificate.subject);
            if let Some(subject_id) = cert.tbs_certificate.subject_unique_id {
                println!("\tID: {:?}", subject_id);
            }
            println!(
                "Serial Nr: {}",
                hex::encode(cert.tbs_certificate.serial_number.as_bytes())
            );
            println!("Signing Algo: {}", oid_name(&cert.signature_algorithm.oid));
            println!("Issue Date: {}", cert.tbs_certificate.validity.not_before);
            println!(
                "Expiration Date: {}",
                cert.tbs_certificate.validity.not_after
            );
            println!("CRL URL(s): {}", crl_urls(&cert.tbs_certificate).join(","));

            continue;
        }

        if let Ok(crl) = CertificateList::from_der(&contents) {
            println!("{} decoded as a Certificate Revocation List", arg);
            print_crl(&crl);
            continue;
        }

        if let Ok(crl_list) = CachedCrl::from_der(&contents) {
            println!(
                "{} decoded as a cached Certificate Revocation List file",
                arg
            );
            println!("CRLs: {}", crl_list.crls.len());

            for crl_pair in &crl_list.crls {
                println!("--------\nURL: {}", crl_pair.url);
                print_crl(&crl_pair.crl);
            }

            continue;
        }

        if let Ok(csr) = CertReq::from_der(&contents) {
            println!("{} decoded as a cached Certificate Signing Request", arg);

            println!("Subject: {}", csr.info.subject);
            println!("Signing Algo: {}", oid_name(&csr.algorithm.oid));
            for Attribute { oid, values } in csr.info.attributes.iter() {
                println!("Attribute OID: {}", oid_name(oid));
                println!("Extensions: {}", values.len());
                for any in values.iter() {
                    let ereq: ExtensionReq<'_> = any.decode_into().unwrap();
                    for ext in Vec::from(ereq) {
                        println!("Extension OID: {}", oid_name(&ext.extn_id));
                        println!("Extension Value: {}", hex::encode(ext.extn_value));
                    }
                }
            }

            continue;
        }

        eprintln!("Failed to decode {}", arg);
    }
}
