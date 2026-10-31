//! Probing: the first conditional request of a job (01 section 3.5, 03 section 7.3).
//!
//! A probe learns size, range support, validators, the file name and whether a session is needed. For a
//! resume it is a ranged `GET` starting at the first uncovered byte, so it doubles as the first data
//! request; the decision table R1 to R11 of 03 section 7.3 is applied to its response.
//!
//! Invariants the implementation keeps:
//!
//! * Redirects are followed **by this layer** (at most 10), never by the transport; session headers are
//!   attached only to requests whose origin equals the granted origin, so a cross-origin redirect
//!   continues without cookies (01 section 4 rule 4).
//! * `Accept-Encoding: identity` always; a `Content-Encoding` other than identity is
//!   `http.content_encoded`.
//! * `Accept-Ranges` is advisory; `range_support` is `verified` only after a `206` with a correct
//!   `Content-Range` was observed.
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use tokio_util::sync::CancellationToken;
use zeus_session::SessionMaterial;
use zeus_types::{HttpUrl, Origin, ProbeResult, Validators};

use crate::error::{HttpError, HttpResult};
use crate::transport::{HttpTransport, ResponseBody};

/// Session material and the one origin it may be sent to.
#[derive(Clone)]
pub struct SessionBinding {
    /// The granted origin. Material is attached only to requests to exactly this origin.
    pub origin: Origin,
    /// The material, shared across the requests of one job.
    pub material: Arc<SessionMaterial>,
}

impl std::fmt::Debug for SessionBinding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionBinding")
            .field("origin", &self.origin)
            .finish_non_exhaustive()
    }
}

/// A resume probe: ask for the bytes from `start` under the bound validators.
#[derive(Debug, Clone)]
pub struct ResumeProbe {
    /// The first uncovered byte.
    pub start: u64,
    /// The validators the committed ranges were fetched under (`If-Range` is derived from them).
    pub bound_validators: Validators,
    /// The total the committed ranges assume.
    pub total_bytes: Option<u64>,
    /// Bytes already on disk just before `start`, for the overlap check when no strong validator exists
    /// (at most 1 MiB).
    pub overlap: Option<bytes::Bytes>,
}

/// What to probe.
#[derive(Debug, Clone)]
pub struct ProbeRequest {
    /// The stable URL (`spec.url`).
    pub url: HttpUrl,
    /// The last known resolved URL, tried first when present.
    pub hint_url: Option<HttpUrl>,
    /// Sent as `Referer` only to the same origin (or an allow-listed one).
    pub referrer: Option<HttpUrl>,
    /// Allow-listed extra headers from the job spec.
    pub extra_headers: BTreeMap<String, String>,
    /// Session material for the granted origin, if the job has a lease.
    pub session: Option<SessionBinding>,
    /// Present when resuming.
    pub resume: Option<ResumeProbe>,
    /// Time allowed per request until the head arrives.
    pub head_timeout: Duration,
    /// Time allowed between body chunks.
    pub idle_timeout: Duration,
}

/// What the probe found.
pub struct ProbeOutcome {
    /// The probe result for the job record and the `job.probed` event.
    pub result: ProbeResult,
    /// The URL that answered (after redirects). Secret-bearing: never log it.
    pub resolved_url: HttpUrl,
    /// For a resume or a plain `GET`, the response body positioned at `body_offset`, so the first bytes
    /// are not requested twice. `None` for `HEAD` and for `0-0` probes whose single byte is discarded.
    pub body: Option<ResponseBody>,
    /// The resource offset of the first byte of `body`.
    pub body_offset: u64,
}

impl std::fmt::Debug for ProbeOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProbeOutcome")
            .field("result", &self.result)
            .field("body_offset", &self.body_offset)
            .finish_non_exhaustive()
    }
}

/// Probes a resource.
#[async_trait]
pub trait Prober: Send + Sync {
    /// Runs the probe. Cancelable at every await. Failures are classified (`HttpError::Classified`);
    /// the resume-validation outcomes R2 to R10 are `integrity.*` errors the engine turns into a restart.
    async fn probe(
        &self,
        request: ProbeRequest,
        cancel: &CancellationToken,
    ) -> HttpResult<ProbeOutcome>;
}

/// The default prober over any [`HttpTransport`].
pub struct HttpProber {
    transport: Arc<dyn HttpTransport>,
}

impl HttpProber {
    /// A prober using `transport`.
    #[must_use]
    pub fn new(transport: Arc<dyn HttpTransport>) -> Self {
        Self { transport }
    }
}

#[async_trait]
impl Prober for HttpProber {
    async fn probe(
        &self,
        request: ProbeRequest,
        cancel: &CancellationToken,
    ) -> HttpResult<ProbeOutcome> {
        use crate::response::{compare_validators, failure, send_following, validators, value};
        use zeus_types::job::HttpVersion;
        use zeus_types::{ProbeMethod, RangeSupport, RedactMode, Timestamp, codes};
        let range = request
            .resume
            .as_ref()
            .map_or_else(|| "bytes=0-0".to_owned(), |r| format!("bytes={}-", r.start));
        let bound = request
            .resume
            .as_ref()
            .and_then(|r| r.bound_validators.if_range_value());
        let probe_url = request.hint_url.clone().unwrap_or(request.url);
        let initial = send_following(
            &self.transport,
            probe_url.clone(),
            &request.extra_headers,
            request.session.as_ref(),
            Some(&range),
            bound,
            request.head_timeout,
            request.idle_timeout,
            cancel,
        )
        .await;
        // Some download gateways reject Range outright instead of ignoring it.
        // Retry a fresh probe once as an ordinary GET; never downgrade a resume,
        // an authentication refusal, or a valid empty-resource response.
        let stream_fallback = request.resume.is_none()
            && match &initial {
                Ok((response, _, _)) => {
                    response.status.as_u16() == 416
                        && value(&response.headers, "content-range").as_deref() != Some("bytes */0")
                }
                Err(HttpError::Classified(error)) => error.code.as_str() == "http.status_400",
                _ => false,
            };
        let (response, resolved_url, redirects) = if stream_fallback {
            drop(initial);
            send_following(
                &self.transport,
                probe_url,
                &request.extra_headers,
                request.session.as_ref(),
                None,
                None,
                request.head_timeout,
                request.idle_timeout,
                cancel,
            )
            .await?
        } else {
            initial?
        };
        let status = response.status.as_u16();
        let seen = validators(&response.headers);
        let mut body_offset = 0;
        let (range_support, total_bytes) = if status == 206 {
            let cr = value(&response.headers, "content-range")
                .ok_or(HttpError::Invalid("206 missing Content-Range"))?;
            match crate::parse::parse_content_range(&cr)? {
                crate::parse::ContentRange::Satisfied { range, total } => {
                    let start = request.resume.as_ref().map_or(0, |r| r.start);
                    if range.start != start || (request.resume.is_none() && range.end != 1) {
                        return Err(failure(
                            codes::INTEGRITY_RANGE_MISMATCH,
                            "probe range does not match request",
                        ));
                    }
                    body_offset = range.start;
                    if let Some(resume) = &request.resume {
                        compare_validators(&resume.bound_validators, &seen)?;
                        if resume.total_bytes.is_some() && resume.total_bytes != total {
                            return Err(failure(
                                codes::INTEGRITY_RESOURCE_CHANGED,
                                "resource length changed",
                            ));
                        }
                        if !resume.bound_validators.is_strongly_identified() {
                            return Err(failure(
                                codes::INTEGRITY_RESOURCE_CHANGED,
                                "resume without strong validator requires a clean restart",
                            ));
                        }
                    }
                    (RangeSupport::Verified, total)
                }
                _ => return Err(HttpError::Invalid("206 has unsatisfied Content-Range")),
            }
        } else if status == 200 {
            if request.resume.is_some() {
                return Err(failure(
                    codes::INTEGRITY_RANGE_IGNORED,
                    "server ignored resume range",
                ));
            }
            (
                RangeSupport::Unsupported,
                value(&response.headers, "content-length").and_then(|v| v.parse().ok()),
            )
        } else if status == 416
            && value(&response.headers, "content-range").as_deref() == Some("bytes */0")
        {
            (RangeSupport::Unsupported, Some(0))
        } else {
            return Err(HttpError::Invalid("unexpected probe response"));
        };
        let filename = response_filename(&resolved_url, &response.headers);
        let result = ProbeResult {
            probed_at: Timestamp::now(),
            method: if stream_fallback {
                ProbeMethod::GetStream
            } else {
                ProbeMethod::RangeGet
            },
            transport: zeus_types::Transport::Direct,
            http_version: Some(if response.version == http::Version::HTTP_2 {
                HttpVersion::H2
            } else {
                HttpVersion::Http11
            }),
            status,
            final_url_redacted: Some(resolved_url.redact(RedactMode::Log)),
            redirects,
            range_support,
            total_bytes,
            content_type: value(&response.headers, "content-type"),
            content_encoding: value(&response.headers, "content-encoding"),
            filename,
            validators: seen,
            requires_session: false,
            interstitial_suspected: false,
        };
        let body = if status == 200 || (status == 206 && request.resume.is_some()) {
            Some(response.body)
        } else {
            None
        };
        Ok(ProbeOutcome {
            result,
            resolved_url,
            body,
            body_offset,
        })
    }
}

// These names remain untrusted: the engine sanitizes them before reserving a path.
// A URL such as /download.php?id=123 is not the document's filename. Use the
// response metadata, including the final redirect URL, without guessing an
// executable suffix or overwriting a person-supplied filename.
fn response_filename(
    url: &zeus_types::HttpUrl,
    headers: &http::HeaderMap,
) -> zeus_types::ResolvedFilename {
    use zeus_types::{ResolvedFilename, job::FilenameSource};
    let disposition = crate::response::value(headers, "content-disposition")
        .and_then(|v| crate::parse::parse_content_disposition(&v).ok().flatten());
    let (mut name, mut source) = match disposition {
        Some(d) => (d.filename, FilenameSource::ContentDisposition),
        None => {
            let segment = url
                .url()
                .path_segments()
                .and_then(|mut p| p.next_back())
                .filter(|s| !s.is_empty())
                .unwrap_or("download");
            (
                percent_encoding::percent_decode_str(segment)
                    .decode_utf8_lossy()
                    .into_owned(),
                FilenameSource::UrlPath,
            )
        }
    };
    let mime = crate::response::value(headers, "content-type").unwrap_or_default();
    let extension = match mime
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
        "application/pdf" => Some("pdf"),
        "application/epub+zip" => Some("epub"),
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document" => Some("docx"),
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" => Some("xlsx"),
        "application/vnd.openxmlformats-officedocument.presentationml.presentation" => Some("pptx"),
        "text/plain" => Some("txt"),
        "text/csv" => Some("csv"),
        _ => None,
    };
    let current = std::path::Path::new(&name)
        .extension()
        .and_then(|v| v.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    if let Some(ext) = extension {
        let script = source == FilenameSource::UrlPath
            && matches!(current.as_str(), "php" | "aspx" | "asp" | "jsp" | "cgi");
        if current.is_empty() || script {
            if script {
                name.truncate(name.len() - current.len() - 1);
            }
            name.push('.');
            name.push_str(ext);
            if source == FilenameSource::UrlPath {
                source = FilenameSource::ContentTypeDefault;
            }
        }
    }
    ResolvedFilename {
        value: name,
        source,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn document_names_follow_response_metadata() {
        for (path, disposition, mime, expected) in [
            ("/download", None, "application/pdf", "download.pdf"),
            (
                "/get.php?id=42",
                None,
                "Application/PDF; charset=binary",
                "get.pdf",
            ),
            (
                "/Quarterly%20Report.pdf",
                None,
                "application/pdf",
                "Quarterly Report.pdf",
            ),
            (
                "/opaque",
                Some("attachment; filename=paper.pdf"),
                "application/octet-stream",
                "paper.pdf",
            ),
            (
                "/opaque",
                Some("attachment; filename=paper"),
                "application/pdf",
                "paper.pdf",
            ),
            ("/archive.zip", None, "application/pdf", "archive.zip"),
            ("/opaque", None, "application/octet-stream", "opaque"),
            ("/opaque", None, "application/x-msdownload", "opaque"),
            ("/", None, "application/pdf", "download.pdf"),
        ] {
            let mut headers = http::HeaderMap::new();
            headers.insert("content-type", mime.parse().unwrap());
            if let Some(value) = disposition {
                headers.insert("content-disposition", value.parse().unwrap());
            }
            let url = zeus_types::HttpUrl::parse(&format!("https://files.example{path}")).unwrap();
            assert_eq!(response_filename(&url, &headers).value, expected, "{path}");
        }
    }

    #[test]
    fn the_prober_trait_is_object_safe() {
        fn takes(_: Option<&dyn Prober>) {}
        takes(None);
    }
}
