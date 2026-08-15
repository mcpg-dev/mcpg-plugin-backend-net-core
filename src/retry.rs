//! Downstream-error classification + retry-guidance shaping shared by
//! the network backend plugins.
//!
//! A non-null `downstreamError` slot in a plugin's response envelope is
//! the gateway's signal to set `is_error` on the projected `tools/call`
//! result (see `execute_http_request` in the gateway). The status-code /
//! content-type / transport classification and the retry-guidance fields
//! are identical across http/grpc/graphql, so they live here; each
//! plugin assembles its own family-specific envelope around this shared
//! [`DownstreamHttpError`].

use serde::Serialize;
use serde_json::Value;

use crate::types::{HttpResponseSummary, RetrySafetyContext};

const DEFAULT_BACKOFF_BASE_MS: u64 = 1_000;

/// Operator-facing per-call error returned in the envelope's
/// `downstreamError` slot. Mirrors the shape the gateway built inline
/// in `apps/gateway/src/runtime/execution.rs` so tools/call clients
/// see the same fields after the lift.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DownstreamHttpError {
    pub kind: String,
    pub code: String,
    pub message: String,
    pub retryable: bool,
    pub retry_class: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry_after_ms: Option<u64>,
    pub idempotency_hint: String,
    pub caller_retry_decision: String,
    pub retry_safety: String,
    pub backoff_strategy: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub minimum_backoff_ms: Option<u64>,
    pub suggested_action: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status_code: Option<u16>,
    pub details: Value,
}

pub fn validate_expected_status_codes(
    expected_status_codes: &[u16],
    actual_status_code: u16,
    retry_after_ms: Option<u64>,
    retry_safety_context: RetrySafetyContext,
) -> Option<DownstreamHttpError> {
    if expected_status_codes.contains(&actual_status_code) {
        return None;
    }
    let retryable = actual_status_code == 429 || actual_status_code >= 500;
    let retry_class = if retryable {
        if retry_after_ms.is_some() {
            "after_delay"
        } else {
            "with_backoff"
        }
    } else {
        "do_not_retry"
    };
    let suggested_action = if retryable {
        if retry_after_ms.is_some() {
            "retry_after_indicated_delay"
        } else {
            "retry_with_backoff_or_check_downstream_capacity"
        }
    } else {
        "inspect_downstream_http_contract"
    };
    Some(with_retry_guidance(
        DownstreamHttpError {
            kind: "unexpected_status_code".to_owned(),
            code: "mcpg.downstream_http.unexpected_status_code".to_owned(),
            message: format!(
                "Downstream response status {} did not match the configured expected status codes.",
                actual_status_code
            ),
            retryable,
            retry_class: retry_class.to_owned(),
            retry_after_ms,
            idempotency_hint: "pending_idempotency_evaluation".to_owned(),
            caller_retry_decision: "pending_caller_retry_decision".to_owned(),
            retry_safety: "pending_retry_safety_evaluation".to_owned(),
            backoff_strategy: "pending_backoff_strategy_evaluation".to_owned(),
            minimum_backoff_ms: None,
            suggested_action: suggested_action.to_owned(),
            status_code: Some(actual_status_code),
            details: serde_json::json!({
                "actualStatusCode": actual_status_code,
                "expectedStatusCodes": expected_status_codes,
                "retryAfterMs": retry_after_ms,
            }),
        },
        retry_safety_context,
    ))
}

pub fn parse_and_validate_json_response(
    response: &HttpResponseSummary,
    require_json_response: bool,
) -> (Option<Value>, Option<String>, Option<DownstreamHttpError>) {
    let content_type_is_json = response
        .content_type
        .as_deref()
        .is_some_and(is_json_content_type);

    if !content_type_is_json {
        if require_json_response {
            return (
                None,
                None,
                Some(json_content_type_downstream_error(
                    response.content_type.as_deref(),
                )),
            );
        }
        return (None, None, None);
    }

    match serde_json::from_str::<Value>(&response.body) {
        Ok(value) => (Some(value), None, None),
        Err(error) => {
            let parse_error = error.to_string();
            let validation_error = if require_json_response {
                Some(json_body_downstream_error(&parse_error))
            } else {
                None
            };
            (None, Some(parse_error), validation_error)
        }
    }
}

pub fn transport_downstream_error(
    error: &str,
    retry_safety_context: RetrySafetyContext,
) -> DownstreamHttpError {
    with_retry_guidance(
        DownstreamHttpError {
            kind: "transport_error".to_owned(),
            code: "mcpg.downstream_http.transport_error".to_owned(),
            message: "Downstream HTTP execution failed before a valid response was received."
                .to_owned(),
            retryable: true,
            retry_class: "with_backoff".to_owned(),
            retry_after_ms: None,
            idempotency_hint: "pending_idempotency_evaluation".to_owned(),
            caller_retry_decision: "pending_caller_retry_decision".to_owned(),
            retry_safety: "safe_for_automatic_retry".to_owned(),
            backoff_strategy: "exponential_backoff".to_owned(),
            minimum_backoff_ms: Some(DEFAULT_BACKOFF_BASE_MS),
            suggested_action: "check_downstream_connectivity_and_retry".to_owned(),
            status_code: None,
            details: serde_json::json!({
                "error": error,
            }),
        },
        retry_safety_context,
    )
}

fn json_content_type_downstream_error(content_type: Option<&str>) -> DownstreamHttpError {
    DownstreamHttpError {
        kind: "invalid_content_type".to_owned(),
        code: "mcpg.downstream_http.invalid_content_type".to_owned(),
        message: "Downstream HTTP JSON call required a JSON response content type, but the response was not JSON.".to_owned(),
        retryable: false,
        retry_class: "do_not_retry".to_owned(),
        retry_after_ms: None,
        idempotency_hint: "potentially_non_idempotent".to_owned(),
        caller_retry_decision: "do_not_retry".to_owned(),
        retry_safety: "do_not_retry".to_owned(),
        backoff_strategy: "no_retry".to_owned(),
        minimum_backoff_ms: None,
        suggested_action: "inspect_downstream_response_content_type".to_owned(),
        status_code: None,
        details: serde_json::json!({
            "responseContentType": content_type,
        }),
    }
}

fn json_body_downstream_error(parse_error: &str) -> DownstreamHttpError {
    DownstreamHttpError {
        kind: "invalid_json_body".to_owned(),
        code: "mcpg.downstream_http.invalid_json_body".to_owned(),
        message: "Downstream HTTP JSON call returned a JSON content type, but the body was not valid JSON.".to_owned(),
        retryable: false,
        retry_class: "do_not_retry".to_owned(),
        retry_after_ms: None,
        idempotency_hint: "potentially_non_idempotent".to_owned(),
        caller_retry_decision: "do_not_retry".to_owned(),
        retry_safety: "do_not_retry".to_owned(),
        backoff_strategy: "no_retry".to_owned(),
        minimum_backoff_ms: None,
        suggested_action: "inspect_downstream_json_payload".to_owned(),
        status_code: None,
        details: serde_json::json!({
            "parseError": parse_error,
        }),
    }
}

fn with_retry_guidance(
    mut error: DownstreamHttpError,
    retry_safety_context: RetrySafetyContext,
) -> DownstreamHttpError {
    let idempotency_hint = match retry_safety_context {
        RetrySafetyContext::ReadOnlyProbe => "idempotent_read_only",
        RetrySafetyContext::PotentiallyNonIdempotentJsonCall => "potentially_non_idempotent",
    };

    if !error.retryable {
        error.idempotency_hint = idempotency_hint.to_owned();
        error.caller_retry_decision = "do_not_retry".to_owned();
        error.retry_safety = "do_not_retry".to_owned();
        error.backoff_strategy = "no_retry".to_owned();
        error.minimum_backoff_ms = None;
        return error;
    }

    let (retry_safety, suggested_action, caller_retry_decision) = match retry_safety_context {
        RetrySafetyContext::ReadOnlyProbe => {
            let decision = if error.retry_after_ms.is_some() {
                "automatic_retry_after_delay"
            } else {
                "automatic_retry_with_backoff"
            };
            (
                "safe_for_automatic_retry",
                error.suggested_action.clone(),
                decision.to_owned(),
            )
        }
        RetrySafetyContext::PotentiallyNonIdempotentJsonCall => {
            let (action, decision) = if error.retry_after_ms.is_some() {
                (
                    "review_idempotency_then_retry_after_delay",
                    "confirm_idempotency_then_retry_after_delay",
                )
            } else {
                (
                    "review_idempotency_then_retry_with_backoff",
                    "confirm_idempotency_then_retry_with_backoff",
                )
            };
            (
                "review_idempotency_before_retry",
                action.to_owned(),
                decision.to_owned(),
            )
        }
    };

    let (backoff_strategy, minimum_backoff_ms) = if let Some(retry_after_ms) = error.retry_after_ms
    {
        ("respect_retry_after", Some(retry_after_ms))
    } else {
        ("exponential_backoff", Some(DEFAULT_BACKOFF_BASE_MS))
    };

    error.idempotency_hint = idempotency_hint.to_owned();
    error.caller_retry_decision = caller_retry_decision;
    error.retry_safety = retry_safety.to_owned();
    error.backoff_strategy = backoff_strategy.to_owned();
    error.minimum_backoff_ms = minimum_backoff_ms;
    error.suggested_action = suggested_action;
    error
}

fn is_json_content_type(content_type: &str) -> bool {
    let media_type = content_type
        .split(';')
        .next()
        .unwrap_or(content_type)
        .trim()
        .to_ascii_lowercase();
    media_type == "application/json" || media_type.ends_with("+json")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matching_status_returns_no_error() {
        assert!(
            validate_expected_status_codes(
                &[200, 204],
                200,
                None,
                RetrySafetyContext::ReadOnlyProbe
            )
            .is_none()
        );
    }

    #[test]
    fn unexpected_5xx_is_retryable() {
        let err =
            validate_expected_status_codes(&[200], 502, None, RetrySafetyContext::ReadOnlyProbe)
                .unwrap();
        assert!(err.retryable);
        assert_eq!(err.kind, "unexpected_status_code");
        assert_eq!(err.status_code, Some(502));
    }

    #[test]
    fn unexpected_4xx_is_not_retryable() {
        let err =
            validate_expected_status_codes(&[200], 400, None, RetrySafetyContext::ReadOnlyProbe)
                .unwrap();
        assert!(!err.retryable);
        assert_eq!(err.suggested_action, "inspect_downstream_http_contract");
    }

    #[test]
    fn rate_limit_with_retry_after_uses_after_delay_class() {
        let err = validate_expected_status_codes(
            &[200],
            429,
            Some(2_500),
            RetrySafetyContext::PotentiallyNonIdempotentJsonCall,
        )
        .unwrap();
        assert!(err.retryable);
        assert_eq!(err.retry_class, "after_delay");
        assert_eq!(err.minimum_backoff_ms, Some(2_500));
        assert_eq!(err.backoff_strategy, "respect_retry_after");
    }

    #[test]
    fn json_content_type_validation() {
        let resp = HttpResponseSummary {
            status_code: 200,
            content_type: Some("application/json".to_owned()),
            retry_after_ms: None,
            body: r#"{"ok":true}"#.to_owned(),
            body_truncated: false,
            duration_ms: 1,
        };
        let (json, parse_err, err) = parse_and_validate_json_response(&resp, true);
        assert_eq!(json.unwrap(), serde_json::json!({"ok": true}));
        assert!(parse_err.is_none());
        assert!(err.is_none());
    }

    #[test]
    fn non_json_with_require_returns_error() {
        let resp = HttpResponseSummary {
            status_code: 200,
            content_type: Some("text/plain".to_owned()),
            retry_after_ms: None,
            body: "hi".to_owned(),
            body_truncated: false,
            duration_ms: 1,
        };
        let (_, _, err) = parse_and_validate_json_response(&resp, true);
        assert_eq!(err.unwrap().kind, "invalid_content_type");
    }

    #[test]
    fn malformed_json_with_require_returns_error() {
        let resp = HttpResponseSummary {
            status_code: 200,
            content_type: Some("application/json".to_owned()),
            retry_after_ms: None,
            body: "{not json".to_owned(),
            body_truncated: false,
            duration_ms: 1,
        };
        let (_, parse_err, err) = parse_and_validate_json_response(&resp, true);
        assert!(parse_err.is_some());
        assert_eq!(err.unwrap().kind, "invalid_json_body");
    }
}
