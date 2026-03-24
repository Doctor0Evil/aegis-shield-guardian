// src/http_gateway.rs (sketch)
use axum::{routing::post, Router, Json};
use serde::{Deserialize, Serialize};
use crate::{AegisGuardian};
use doctorlabssuperfilter::SpanScore;

#[derive(Deserialize)]
pub struct AnalyzeRequest {
    pub session_id: String,
    pub spans: Vec<SpanScore>,
}

#[derive(Serialize)]
pub struct AnalyzeResponse {
    pub mode: String,
    pub roguescore: f64,
}

pub fn router(guardian: AegisGuardian) -> Router {
    Router::new().route(
        "/aegis/analyze",
        post(move |Json(req): Json<AnalyzeRequest>| {
            let decision = guardian.decide(&req.spans);
            let mode = format!("{:?}", decision.mode);
            Json(AnalyzeResponse { mode, roguescore: decision.roguescore.rtotal })
        }),
    )
}
