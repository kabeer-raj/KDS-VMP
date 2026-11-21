use scan_worker::lifecycle::{ScanStateMachine, WorkerPhase};
use shared_types::enums::ScanStatus;
use uuid::Uuid;

#[test]
fn test_state_machine_initial_state() {
    let scan_id = Uuid::new_v4();
    let app_id = Uuid::new_v4();
    let sm = ScanStateMachine::new(scan_id, app_id);

    assert_eq!(sm.scan_id(), scan_id);
    assert_eq!(sm.app_id(), app_id);
    assert_eq!(sm.status(), ScanStatus::Queued);
    assert_eq!(sm.phase(), WorkerPhase::Queued);
    assert_eq!(sm.phase().as_str(), "queued");
}

#[test]
fn test_state_machine_valid_full_lifecycle() {
    let mut sm = ScanStateMachine::new(Uuid::new_v4(), Uuid::new_v4());

    // Queued -> Spidering (Running)
    assert!(sm.transition_to(ScanStatus::Spidering).is_ok());
    assert_eq!(sm.status(), ScanStatus::Spidering);
    assert_eq!(sm.phase(), WorkerPhase::Running);
    assert_eq!(sm.phase().as_str(), "running");

    // Spidering -> ActiveScanning (Running)
    assert!(sm.transition_to(ScanStatus::ActiveScanning).is_ok());
    assert_eq!(sm.status(), ScanStatus::ActiveScanning);
    assert_eq!(sm.phase(), WorkerPhase::Running);

    // ActiveScanning -> Ingesting (Analyzing)
    assert!(sm.transition_to(ScanStatus::Ingesting).is_ok());
    assert_eq!(sm.status(), ScanStatus::Ingesting);
    assert_eq!(sm.phase(), WorkerPhase::Analyzing);
    assert_eq!(sm.phase().as_str(), "analyzing");

    // Ingesting -> Completed
    assert!(sm.transition_to(ScanStatus::Completed).is_ok());
    assert_eq!(sm.status(), ScanStatus::Completed);
    assert_eq!(sm.phase(), WorkerPhase::Completed);
    assert_eq!(sm.phase().as_str(), "completed");
}

#[test]
fn test_state_machine_terminal_state_transitions_rejected() {
    let mut sm = ScanStateMachine::new(Uuid::new_v4(), Uuid::new_v4());
    sm.transition_to(ScanStatus::Spidering).unwrap();
    sm.transition_to(ScanStatus::Ingesting).unwrap();
    sm.transition_to(ScanStatus::Completed).unwrap();

    // From Completed, cannot transition to any other state
    assert!(sm.transition_to(ScanStatus::ActiveScanning).is_err());
    assert!(sm.transition_to(ScanStatus::Queued).is_err());
    assert!(sm.transition_to(ScanStatus::Failed).is_err());
    assert!(sm.transition_to(ScanStatus::Cancelled).is_err());

    // Same state transition is idempotent (Ok)
    assert!(sm.transition_to(ScanStatus::Completed).is_ok());
}

#[test]
fn test_state_machine_cancellation_from_any_active_state() {
    let states = [
        ScanStatus::Queued,
        ScanStatus::Spidering,
        ScanStatus::ActiveScanning,
        ScanStatus::Ingesting,
    ];

    for initial in states {
        let mut sm = ScanStateMachine::new(Uuid::new_v4(), Uuid::new_v4());
        if initial != ScanStatus::Queued {
            sm.transition_to(initial).unwrap();
        }
        assert!(sm.transition_to(ScanStatus::Cancelled).is_ok());
        assert_eq!(sm.status(), ScanStatus::Cancelled);
        assert_eq!(sm.phase(), WorkerPhase::Cancelled);
    }
}

#[test]
fn test_state_machine_failure_from_any_active_state() {
    let states = [
        ScanStatus::Queued,
        ScanStatus::Spidering,
        ScanStatus::ActiveScanning,
        ScanStatus::Ingesting,
    ];

    for initial in states {
        let mut sm = ScanStateMachine::new(Uuid::new_v4(), Uuid::new_v4());
        if initial != ScanStatus::Queued {
            sm.transition_to(initial).unwrap();
        }
        assert!(sm.transition_to(ScanStatus::Failed).is_ok());
        assert_eq!(sm.status(), ScanStatus::Failed);
        assert_eq!(sm.phase(), WorkerPhase::Failed);
    }
}
