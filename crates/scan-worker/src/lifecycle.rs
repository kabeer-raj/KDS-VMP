use crate::error::ScanWorkerError;
use shared_types::enums::ScanStatus;
use uuid::Uuid;

/// High-level worker lifecycle phases corresponding to the background scan engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WorkerPhase {
    Queued,
    Running,    // Spidering or ActiveScanning
    Analyzing,  // Ingesting, deduplicating, scoring, diffing, persisting
    Completed,
    Failed,
    Cancelled,
}

impl WorkerPhase {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Running => "running",
            Self::Analyzing => "analyzing",
            Self::Completed => "completed",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
        }
    }
}

/// Scan lifecycle state machine tracking status transitions and validating allowed flows:
/// Queued -> Running -> Analyzing -> Completed / Failed / Cancelled.
#[derive(Debug, Clone)]
pub struct ScanStateMachine {
    scan_id: Uuid,
    app_id: Uuid,
    status: ScanStatus,
    phase: WorkerPhase,
}

impl ScanStateMachine {
    pub fn new(scan_id: Uuid, app_id: Uuid) -> Self {
        Self {
            scan_id,
            app_id,
            status: ScanStatus::Queued,
            phase: WorkerPhase::Queued,
        }
    }

    pub fn scan_id(&self) -> Uuid {
        self.scan_id
    }

    pub fn app_id(&self) -> Uuid {
        self.app_id
    }

    pub fn status(&self) -> ScanStatus {
        self.status
    }

    pub fn phase(&self) -> WorkerPhase {
        self.phase
    }

    /// Validates whether a state transition from the current status to `new_status` is permitted.
    pub fn can_transition_to(&self, new_status: ScanStatus) -> bool {
        match (self.status, new_status) {
            // Same status is always permitted (idempotent)
            (a, b) if a == b => true,

            // Queued -> Running (Spidering / ActiveScanning) or Analyzing (Ingesting) or Terminal
            (ScanStatus::Queued, ScanStatus::Spidering) => true,
            (ScanStatus::Queued, ScanStatus::ActiveScanning) => true,
            (ScanStatus::Queued, ScanStatus::Ingesting) => true,
            (ScanStatus::Queued, ScanStatus::Cancelled) => true,
            (ScanStatus::Queued, ScanStatus::Failed) => true,

            // Spidering -> ActiveScanning or Ingesting (Analyzing) or Terminal
            (ScanStatus::Spidering, ScanStatus::ActiveScanning) => true,
            (ScanStatus::Spidering, ScanStatus::Ingesting) => true,
            (ScanStatus::Spidering, ScanStatus::Cancelled) => true,
            (ScanStatus::Spidering, ScanStatus::Failed) => true,

            // ActiveScanning -> Ingesting (Analyzing) or Terminal
            (ScanStatus::ActiveScanning, ScanStatus::Ingesting) => true,
            (ScanStatus::ActiveScanning, ScanStatus::Cancelled) => true,
            (ScanStatus::ActiveScanning, ScanStatus::Failed) => true,

            // Ingesting (Analyzing) -> Completed or Terminal
            (ScanStatus::Ingesting, ScanStatus::Completed) => true,
            (ScanStatus::Ingesting, ScanStatus::Cancelled) => true,
            (ScanStatus::Ingesting, ScanStatus::Failed) => true,

            // Terminal states cannot transition to anything
            (ScanStatus::Completed, _) => false,
            (ScanStatus::Failed, _) => false,
            (ScanStatus::Cancelled, _) => false,

            // Default fallback for any other unhandled transition
            _ => false,
        }
    }

    /// Performs the state transition or returns an error if the transition is disallowed.
    pub fn transition_to(&mut self, new_status: ScanStatus) -> Result<(), ScanWorkerError> {
        if !self.can_transition_to(new_status) {
            return Err(ScanWorkerError::InvalidState(format!(
                "Invalid scan state transition from {:?} to {:?}",
                self.status, new_status
            )));
        }

        self.status = new_status;
        self.phase = match new_status {
            ScanStatus::Queued => WorkerPhase::Queued,
            ScanStatus::Spidering | ScanStatus::ActiveScanning => WorkerPhase::Running,
            ScanStatus::Ingesting => WorkerPhase::Analyzing,
            ScanStatus::Completed => WorkerPhase::Completed,
            ScanStatus::Failed => WorkerPhase::Failed,
            ScanStatus::Cancelled => WorkerPhase::Cancelled,
        };

        Ok(())
    }
}
