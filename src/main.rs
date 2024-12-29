use std::{collections::HashSet, hash::Hash, time::Duration};

use anyhow::Context;
use askama_axum::{IntoResponse, Response, Template};
use axum::{
    extract::{Query, Request},
    response::Redirect,
    Form, Router,
};
use hickory_resolver::{
    config::{ResolverConfig, ResolverOpts},
    error::ResolveErrorKind,
    proto::rr::RecordType,
    TokioAsyncResolver,
};
use serde::Deserialize;
use tower_http::{classify::ServerErrorsFailureClass, trace::TraceLayer};
use tracing::{info, info_span, Span};
use x509_parser::prelude::{FromDer, GeneralName, X509Certificate};

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    let port = std::env::var("PORT").unwrap().parse::<u16>().unwrap();
    let bind_addr = format!("0.0.0.0:{}", port);

    let app = Router::new()
        .route("/", axum::routing::get(handle_get).post(handle_post))
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(|request: &Request<_>| {
                    info_span!(
                        "http_request",
                        method = ?request.method(),
                        request_uri = ?request.uri(),
                        latency = tracing::field::Empty,
                    )
                })
                .on_response(|response: &Response, latency: Duration, span: &Span| {
                    span.record("latency", latency.as_millis());
                    info!(status = ?response.status(), "request completed");
                })
                .on_failure(
                    |error: ServerErrorsFailureClass, latency: Duration, span: &Span| {
                        span.record("latency", latency.as_millis());
                        info!(status = ?error, "request failed");
                    },
                ),
        );
    let listener = tokio::net::TcpListener::bind(&bind_addr).await.unwrap();

    info!(bind_addr, "starting");

    axum::serve(listener, app).await.unwrap();
}

#[derive(Debug, Deserialize)]
struct QueryParams {
    domain: Option<String>,
}

#[derive(Debug, Deserialize)]
struct FormParams {
    domain: String,
}

#[derive(Template)]
#[template(path = "index.html.j2")]
struct IndexTemplate {
    domain: Option<AcceptableDomain>,
    certificate_info: Option<Result<CertificateInfo, anyhow::Error>>,
    dns_info: Option<DnsInfo>,
}

async fn handle_get(Query(query_params): Query<QueryParams>) -> Response {
    IndexTemplate {
        domain: AcceptableDomain::new(query_params.domain.unwrap_or_default()).ok(),
        certificate_info: None,
        dns_info: None,
    }
    .into_response()
}

async fn handle_post(
    Query(query_params): Query<QueryParams>,
    Form(form_params): Form<FormParams>,
) -> Response {
    match AcceptableDomain::new(form_params.domain.clone()) {
        Err(e) => Response::builder()
            .status(400)
            .body(format!("Invalid domain: {}", e))
            .unwrap()
            .into_response(),
        Ok(form_domain) => {
            if query_params.domain.unwrap_or_default() != form_domain.domain {
                Redirect::temporary(&format!("/?domain={}", form_domain.domain)).into_response()
            } else {
                IndexTemplate {
                    domain: Some(form_domain.clone()),
                    certificate_info: Some(get_certificate_info(&form_domain).await),
                    dns_info: Some(get_dns_info(&form_domain).await),
                }
                .into_response()
            }
        }
    }
}

#[derive(Debug, Clone)]
struct AcceptableDomain {
    domain: String,
}

impl AcceptableDomain {
    fn new(domain: String) -> Result<Self, anyhow::Error> {
        let prepared_domain = domain
            .to_lowercase()
            .trim()
            .trim_matches('/')
            .trim_matches('.')
            .replace("https://", "")
            .replace("http://", "");

        if prepared_domain.is_empty() {
            anyhow::bail!("Domain is empty");
        }

        if prepared_domain.len() < 3 {
            anyhow::bail!("Domain is too short");
        }

        if prepared_domain.len() > 64 {
            anyhow::bail!("Domain is too long");
        }

        if !prepared_domain.contains(".") {
            anyhow::bail!("Domain does not contain a dot");
        }

        if prepared_domain
            .chars()
            .any(|c| !c.is_ascii_alphanumeric() && c != '-' && c != '.')
        {
            anyhow::bail!("Domain contains invalid characters");
        }

        if prepared_domain.starts_with('-') || domain.ends_with('-') {
            anyhow::bail!("Domain starts or ends with a hyphen");
        }

        if prepared_domain.contains("..") {
            anyhow::bail!("Domain contains consecutive dots");
        }

        Ok(Self {
            domain: prepared_domain,
        })
    }

    fn fqdn_without_www(&self) -> String {
        self.fqdn_as_entered()
            .strip_prefix("www.")
            .unwrap_or(&self.fqdn_as_entered())
            .to_string()
    }

    fn fqdn_with_www(&self) -> String {
        format!("www.{}", self.fqdn_without_www())
    }

    fn fqdn_as_entered(&self) -> String {
        format!("{}.", self.domain)
    }
}

#[derive(Debug)]
struct CertificateInfo {
    issuer: String,
    subject: String,
    domain_names: Vec<String>,
    not_before: String,
    not_after: String,
}

async fn get_certificate_info(domain: &AcceptableDomain) -> Result<CertificateInfo, anyhow::Error> {
    let client = reqwest::Client::builder().tls_info(true).build()?;
    let resp = client
        .get(format!("https://{}", domain.domain))
        .send()
        .await?;
    let tls_info = resp
        .extensions()
        .get::<reqwest::tls::TlsInfo>()
        .context("No TLS info")?;
    let (_, certificate) =
        X509Certificate::from_der(tls_info.peer_certificate().context("No TLS certificate")?)?;

    Ok(CertificateInfo {
        issuer: certificate.tbs_certificate.issuer.to_string(),
        subject: certificate.tbs_certificate.subject.to_string(),
        domain_names: certificate
            .tbs_certificate
            .subject_alternative_name()?
            .context("No alternative names")?
            .value
            .general_names
            .iter()
            .filter_map(|name| match name {
                GeneralName::DNSName(name) => Some(name.to_string()),
                _ => None,
            })
            .collect(),
        not_before: certificate.tbs_certificate.validity.not_before.to_string(),
        not_after: certificate.tbs_certificate.validity.not_after.to_string(),
    })
}

#[derive(Debug)]
struct DnsInfo {
    records: Vec<DnsInfoRecord>,
    errors: Vec<String>,
}

#[derive(Debug, PartialEq, Eq, Hash)]
struct DnsInfoRecord {
    name: String,
    record_type: String,
    data: String,
}

async fn get_dns_info(domain: &AcceptableDomain) -> DnsInfo {
    let resolver = TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default());

    let mut unique_records = HashSet::new();
    let mut errors = Vec::new();

    for record_type in &[
        RecordType::A,
        RecordType::AAAA,
        RecordType::NS,
        RecordType::MX,
        RecordType::TXT,
        RecordType::SRV,
        RecordType::CNAME,
    ] {
        for fqdn in &[
            domain.fqdn_with_www(),
            domain.fqdn_without_www(),
        ] {
            match resolver.lookup(fqdn, *record_type).await {
                Ok(lookup) => {
                    unique_records.extend(lookup.record_iter().map(|record| DnsInfoRecord {
                        name: record.name().to_string(),
                        record_type: record.record_type().to_string(),
                        data: record.data().map(|d| d.to_string()).unwrap_or_default(),
                    }))
                }
                Err(e) => match e.kind() {
                    ResolveErrorKind::NoRecordsFound { .. } => (),
                    e => errors.push(e.to_string()),
                },
            }
        }
    }

    let mut records: Vec<DnsInfoRecord> = unique_records.into_iter().collect();
    records.sort_by_key(|r| (r.name.clone(), r.record_type.clone(), r.data.clone()));

    DnsInfo { records, errors }
}
