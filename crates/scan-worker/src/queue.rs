use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use shared_types::enums::ScanType;
use tokio::sync::RwLock;
use uuid::Uuid;

/// Representation of a scan execution job dequeued by the worker.
#[derive(Debug, Clone)]
pub struct ScanJob {
    pub scan_id: Uuid,
    pub application_id: Uuid,
    pub target_url: String,
    pub scan_type: ScanType,
    pub custom_headers: Option<HashMap<String, String>>,
}

/// In-memory queue adapter for asynchronous scan job dispatch and consumption.
#[derive(Default, Clone)]
pub struct InMemoryScanJobQueue {
    queue: Arc<RwLock<VecDeque<ScanJob>>>,
}

impl InMemoryScanJobQueue {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn enqueue(&self, job: ScanJob) {
        let mut q = self.queue.write().await;
        q.push_back(job);
    }

    pub async fn dequeue(&self) -> Option<ScanJob> {
        let mut q = self.queue.write().await;
        q.pop_front()
    }

    pub async fn len(&self) -> usize {
        let q = self.queue.read().await;
        q.len()
    }

    pub async fn is_empty(&self) -> bool {
        let q = self.queue.read().await;
        q.is_empty()
    }
}
