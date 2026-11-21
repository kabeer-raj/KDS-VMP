use infra::pubsub::InMemoryPubSub;
use infra::traits::PubSubPort;
use shared_types::{ScanProgressEvent, ScanStatus, WsServerEvent};
use uuid::Uuid;

#[tokio::test]
async fn test_in_memory_pubsub_broadcast() {
    let pubsub = InMemoryPubSub::new();
    let scan_id = Uuid::new_v4();
    let app_id = Uuid::new_v4();

    let mut rx1 = pubsub.subscribe_scan_progress(scan_id).await.expect("subscribe failed");
    let mut rx2 = pubsub.subscribe_scan_progress(scan_id).await.expect("subscribe 2 failed");

    let event = WsServerEvent::ScanProgress(ScanProgressEvent {
        scan_id,
        application_id: app_id,
        status: ScanStatus::ActiveScanning,
        progress_percent: 45,
        current_phase: "Testing SQL Injection".to_string(),
        alerts_found_so_far: 3,
    });

    pubsub.publish_scan_progress(&event).await.expect("publish failed");

    // Both subscribers should receive the event
    let received_1 = rx1.recv().await.expect("rx1 receive failed");
    match received_1 {
        WsServerEvent::ScanProgress(p) => {
            assert_eq!(p.scan_id, scan_id);
            assert_eq!(p.progress_percent, 45);
            assert_eq!(p.current_phase, "Testing SQL Injection");
            assert_eq!(p.alerts_found_so_far, 3);
        }
        _ => panic!("unexpected event variant"),
    }

    let received_2 = rx2.recv().await.expect("rx2 receive failed");
    match received_2 {
        WsServerEvent::ScanProgress(p) => {
            assert_eq!(p.scan_id, scan_id);
            assert_eq!(p.progress_percent, 45);
        }
        _ => panic!("unexpected event variant"),
    }
}
