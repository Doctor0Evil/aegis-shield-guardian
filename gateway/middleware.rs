use axum::{Json, extract::State};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::guardian::guardian::AegisGuardian;

#[derive(Deserialize)]
pub struct AnalyzeRequest {

    pub session_id: String,

    pub text: String,
}

#[derive(Serialize)]
pub struct AnalyzeResponse {

    pub mode: String,
}

pub async fn analyze(
    State(_guardian): State<Arc<AegisGuardian>>,
    Json(_req): Json<AnalyzeRequest>,
) -> Json<AnalyzeResponse> {

    Json(AnalyzeResponse {
        mode: "Normal".into()
    })
}
