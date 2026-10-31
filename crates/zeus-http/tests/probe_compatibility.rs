//! Real prober/HTTP policy against scripted transport responses, without public-site dependence.
use async_trait::async_trait;
use bytes::Bytes;
use futures::{StreamExt, stream};
use http::{HeaderMap, StatusCode, Version};
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio_util::sync::CancellationToken;
use zeus_http::{
    HttpProber, HttpRequest, HttpResponse, HttpTransport, ProbeRequest, Prober, ResumeProbe,
    TransportError,
};
use zeus_types::{HttpUrl, ProbeMethod, RangeSupport, Validators};

struct Gateway {
    status: u16,
    empty: bool,
    ranges: Mutex<Vec<bool>>,
}
#[async_trait]
impl HttpTransport for Gateway {
    async fn send(&self, request: HttpRequest) -> Result<HttpResponse, TransportError> {
        let ranged = request.headers.contains_key("range");
        self.ranges.lock().unwrap().push(ranged);
        let mut headers = HeaderMap::new();
        headers.insert("content-type", "application/pdf".parse().unwrap());
        if ranged && self.empty {
            headers.insert("content-range", "bytes */0".parse().unwrap());
        }
        let data: &'static [u8] = if ranged { b"" } else { b"%PDF-1.7\nfixture" };
        headers.insert("content-length", data.len().to_string().parse().unwrap());
        Ok(HttpResponse {
            status: StatusCode::from_u16(if ranged { self.status } else { 200 }).unwrap(),
            version: Version::HTTP_11,
            headers,
            url: request.url,
            body: Box::pin(stream::iter([Ok(Bytes::from_static(data))])),
        })
    }
}
fn request() -> ProbeRequest {
    ProbeRequest {
        url: HttpUrl::parse("https://files.example/download?id=42").unwrap(),
        hint_url: None,
        referrer: None,
        extra_headers: BTreeMap::new(),
        session: None,
        resume: None,
        head_timeout: Duration::from_secs(1),
        idle_timeout: Duration::from_secs(1),
    }
}
#[tokio::test]
async fn rejecting_ranges_falls_back_once_and_keeps_the_complete_pdf_body() {
    for status in [400, 416] {
        let transport = Arc::new(Gateway {
            status,
            empty: false,
            ranges: Mutex::new(vec![]),
        });
        let mut outcome = HttpProber::new(transport.clone())
            .probe(request(), &CancellationToken::new())
            .await
            .unwrap();
        assert_eq!(*transport.ranges.lock().unwrap(), vec![true, false]);
        assert_eq!(outcome.result.method, ProbeMethod::GetStream);
        assert_eq!(outcome.result.range_support, RangeSupport::Unsupported);
        assert_eq!(outcome.result.filename.value, "download.pdf");
        assert_eq!(
            outcome.body.take().unwrap().next().await.unwrap().unwrap(),
            Bytes::from_static(b"%PDF-1.7\nfixture")
        );
    }
}
#[tokio::test]
async fn forbidden_and_resume_responses_never_silently_downgrade() {
    for (status, resume) in [(403, false), (416, true)] {
        let transport = Arc::new(Gateway {
            status,
            empty: false,
            ranges: Mutex::new(vec![]),
        });
        let mut req = request();
        if resume {
            req.resume = Some(ResumeProbe {
                start: 10,
                bound_validators: Validators::default(),
                total_bytes: Some(20),
                overlap: None,
            });
        }
        assert!(
            HttpProber::new(transport.clone())
                .probe(req, &CancellationToken::new())
                .await
                .is_err()
        );
        assert_eq!(*transport.ranges.lock().unwrap(), vec![true]);
    }
}
#[tokio::test]
async fn empty_resource_does_not_issue_a_second_request() {
    let transport = Arc::new(Gateway {
        status: 416,
        empty: true,
        ranges: Mutex::new(vec![]),
    });
    let result = HttpProber::new(transport.clone())
        .probe(request(), &CancellationToken::new())
        .await
        .unwrap();
    assert_eq!(result.result.total_bytes, Some(0));
    assert_eq!(*transport.ranges.lock().unwrap(), vec![true]);
}
