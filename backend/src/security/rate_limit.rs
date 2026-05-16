use std::{sync::Arc, time::Duration};
use governor::middleware::NoOpMiddleware;
use tower_governor::{
    governor::{GovernorConfig, GovernorConfigBuilder},
    key_extractor::PeerIpKeyExtractor,
    GovernorLayer,
};

type Conf = GovernorConfig<PeerIpKeyExtractor, NoOpMiddleware>;

pub struct RateLimitConfigs {
    pub auth:    Arc<Conf>,
    pub general: Arc<Conf>,
}

impl RateLimitConfigs {
    pub fn new() -> Self {
        let auth_conf = GovernorConfigBuilder::default()
            .per_second(10)
            .burst_size(5)
            .finish()
            .expect("Failed to build auth rate limit config");

        let general_conf = GovernorConfigBuilder::default()
            .per_second(2)
            .burst_size(30)
            .finish()
            .expect("Failed to build general rate limit config");

        Self {
            auth:    Arc::new(auth_conf),
            general: Arc::new(general_conf),
        }
    }
}

pub fn auth_rate_limit_layer(
    config: Arc<Conf>,
) -> GovernorLayer<PeerIpKeyExtractor, NoOpMiddleware> {
    GovernorLayer { config }
}

pub fn general_rate_limit_layer(
    config: Arc<Conf>,
) -> GovernorLayer<PeerIpKeyExtractor, NoOpMiddleware> {
    GovernorLayer { config }
}

pub fn spawn_cleanup_task(configs: &RateLimitConfigs, interval_secs: u64) {
    let auth_limiter    = Arc::clone(configs.auth.limiter());
    let general_limiter = Arc::clone(configs.general.limiter());
    let interval        = Duration::from_secs(interval_secs);

    tokio::spawn(async move {
        let mut tick = tokio::time::interval(interval);
        loop {
            tick.tick().await;
            auth_limiter.retain_recent();
            general_limiter.retain_recent();
            tracing::debug!("Rate limiter: cleaned up stale entries");
        }
    });
}