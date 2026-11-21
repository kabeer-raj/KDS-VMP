use async_trait::async_trait;
use tokio::sync::broadcast;
use uuid::Uuid;

use crate::error::InfraError;
use crate::traits::PubSubPort;
use shared_types::WsServerEvent;

pub struct InMemoryPubSub {
    sender: broadcast::Sender<WsServerEvent>,
}

impl InMemoryPubSub {
    pub fn new() -> Self {
        let (sender, _) = broadcast::channel(1024);
        Self { sender }
    }
}

impl Default for InMemoryPubSub {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl PubSubPort for InMemoryPubSub {
    async fn publish_scan_progress(&self, event: &WsServerEvent) -> Result<(), InfraError> {
        // broadcast sends to all active subscribers. If there are no receivers, Ok(_) with 0 is fine.
        let _ = self.sender.send(event.clone());
        Ok(())
    }

    async fn subscribe_scan_progress(&self, _scan_id: Uuid) -> Result<broadcast::Receiver<WsServerEvent>, InfraError> {
        Ok(self.sender.subscribe())
    }
}
