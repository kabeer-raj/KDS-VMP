use async_trait::async_trait;
use redis::AsyncCommands;
use tokio::sync::broadcast;
use uuid::Uuid;

use crate::error::InfraError;
use crate::memory::pubsub::InMemoryPubSub;
use crate::traits::PubSubPort;
use shared_types::WsServerEvent;

pub struct RedisPubSub {
    client: Option<redis::Client>,
    fallback: InMemoryPubSub,
}

impl RedisPubSub {
    pub fn new(redis_url: Option<&str>) -> Self {
        let client = redis_url.and_then(|url| redis::Client::open(url).ok());
        Self {
            client,
            fallback: InMemoryPubSub::new(),
        }
    }
}

impl Default for RedisPubSub {
    fn default() -> Self {
        Self::new(None)
    }
}

#[async_trait]
impl PubSubPort for RedisPubSub {
    async fn publish_scan_progress(&self, event: &WsServerEvent) -> Result<(), InfraError> {
        let serialized = serde_json::to_string(event)?;

        // Broadcast to local in-memory subscribers first
        let _ = self.fallback.publish_scan_progress(event).await;

        if let Some(ref client) = self.client {
            if let Ok(mut conn) = client.get_multiplexed_async_connection().await {
                let channel = match event {
                    WsServerEvent::ScanProgress(p) => format!("scan:progress:{}", p.scan_id),
                    WsServerEvent::ScanCompleted(c) => format!("scan:progress:{}", c.scan_id),
                    WsServerEvent::ScanFailed(f) => format!("scan:progress:{}", f.scan_id),
                };
                let res: Result<(), redis::RedisError> = conn.publish(&channel, serialized).await;
                if let Err(e) = res {
                    tracing::warn!("Redis publish failed, using in-memory broadcast: {}", e);
                }
            }
        }

        Ok(())
    }

    async fn subscribe_scan_progress(&self, scan_id: Uuid) -> Result<broadcast::Receiver<WsServerEvent>, InfraError> {
        self.fallback.subscribe_scan_progress(scan_id).await
    }
}
