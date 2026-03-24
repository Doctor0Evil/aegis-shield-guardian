use aegis_shield_guardian::guardian::guardian::AegisGuardian;
use aegis_shield_guardian::gateway::http::start_gateway;

#[tokio::main]
async fn main() {

    tracing_subscriber::fmt::init();

    let guardian = AegisGuardian::boot(
        "config/rogue-config.yaml",
        "policies/"
    );

    start_gateway(guardian).await;
}
