use axum::{Router, routing::post};
use std::sync::Arc;

use crate::guardian::guardian::AegisGuardian;

pub async fn start_gateway(guardian: AegisGuardian) {

    let guardian = Arc::new(guardian);

    let app = Router::new()
        .route("/analyze", post(crate::gateway::middleware::analyze))
        .with_state(guardian);

    axum::Server::bind(&"0.0.0.0:8080".parse().unwrap())
        .serve(app.into_make_service())
        .await
        .unwrap();
}
