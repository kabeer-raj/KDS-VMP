import {
  ScanCompletedEvent,
  ScanFailedEvent,
  ScanProgressEvent,
  ScanStatus,
  WsServerEvent,
} from '../types';
import { api } from './api';

export type WsConnectionStatus = 'connecting' | 'connected' | 'disconnected' | 'error';
export type WsStatusListener = (status: WsConnectionStatus) => void;
export type WsEventListener = (event: WsServerEvent) => void;
export type ScanProgressListener = (data: ScanProgressEvent) => void;
export type ScanCompletedListener = (data: ScanCompletedEvent) => void;
export type ScanFailedListener = (data: ScanFailedEvent) => void;

export class ScanWebSocketClient {
  private socket: WebSocket | null = null;
  private scanId: string | null = null;
  private status: WsConnectionStatus = 'disconnected';
  private reconnectAttempts = 0;
  private maxReconnectAttempts = 5;
  private reconnectTimeout: number | null = null;
  private mockInterval: number | null = null;

  // Listeners
  private statusListeners: Set<WsStatusListener> = new Set();
  private eventListeners: Set<WsEventListener> = new Set();
  private progressListeners: Set<ScanProgressListener> = new Set();
  private completedListeners: Set<ScanCompletedListener> = new Set();
  private failedListeners: Set<ScanFailedListener> = new Set();

  constructor() {}

  public getStatus(): WsConnectionStatus {
    return this.status;
  }

  private setStatus(newStatus: WsConnectionStatus) {
    if (this.status !== newStatus) {
      this.status = newStatus;
      this.statusListeners.forEach((listener) => {
        try {
          listener(newStatus);
        } catch (e) {
          console.error('[WebSocket] Error in status listener:', e);
        }
      });
    }
  }

  /**
   * Connect to a specific scan stream (/ws/v1/scans/:id?token=...)
   */
  public connect(scanId: string, customToken?: string) {
    this.disconnect();
    this.scanId = scanId;

    if (api.getMockMode()) {
      this.startMockSimulation(scanId);
      return;
    }

    const token = customToken || api.getAccessToken();
    const tokenQuery = token ? `?token=${encodeURIComponent(token)}` : '';

    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const isDev = window.location.port === '1420' || window.location.port === '5173' || !window.location.host;
    const defaultWsHost = isDev ? 'ws://127.0.0.1:8000' : `${protocol}//${window.location.host}`;
    const apiHost = import.meta.env.VITE_WS_URL || defaultWsHost;
    const wsUrl = `${apiHost}/ws/v1/scans/${scanId}${tokenQuery}`;

    this.setStatus('connecting');

    try {
      this.socket = new WebSocket(wsUrl);

      this.socket.onopen = () => {
        this.reconnectAttempts = 0;
        this.setStatus('connected');
      };

      this.socket.onmessage = (event: MessageEvent) => {
        try {
          const parsed = JSON.parse(event.data) as WsServerEvent;
          this.handleServerEvent(parsed);
        } catch (err) {
          console.error('[WebSocket] Failed to parse server message:', err);
        }
      };

      this.socket.onerror = (error) => {
        console.warn('[WebSocket] Connection error:', error);
        this.setStatus('error');
      };

      this.socket.onclose = (event) => {
        this.setStatus('disconnected');
        this.socket = null;

        // Auto-reconnect if not closed cleanly
        if (!event.wasClean && this.scanId && this.reconnectAttempts < this.maxReconnectAttempts) {
          const delay = Math.min(1000 * Math.pow(2, this.reconnectAttempts), 10000);
          this.reconnectAttempts++;
          this.reconnectTimeout = window.setTimeout(() => {
            if (this.scanId) {
              this.connect(this.scanId, customToken);
            }
          }, delay);
        }
      };
    } catch {
      this.setStatus('error');
    }
  }

  /**
   * Connect to global notification stream (/ws/v1/notifications?token=...)
   */
  public connectNotifications(customToken?: string) {
    this.disconnect();

    if (api.getMockMode()) {
      this.setStatus('connected');
      return;
    }

    const token = customToken || api.getAccessToken();
    const tokenQuery = token ? `?token=${encodeURIComponent(token)}` : '';
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const isDev = window.location.port === '1420' || window.location.port === '5173' || !window.location.host;
    const defaultWsHost = isDev ? 'ws://127.0.0.1:8000' : `${protocol}//${window.location.host}`;
    const apiHost = import.meta.env.VITE_WS_URL || defaultWsHost;
    const wsUrl = `${apiHost}/ws/v1/notifications${tokenQuery}`;

    this.setStatus('connecting');

    try {
      this.socket = new WebSocket(wsUrl);
      this.socket.onopen = () => this.setStatus('connected');
      this.socket.onmessage = (event) => {
        try {
          const parsed = JSON.parse(event.data) as WsServerEvent;
          this.handleServerEvent(parsed);
        } catch {
          // ignore
        }
      };
      this.socket.onerror = () => this.setStatus('error');
      this.socket.onclose = () => {
        this.setStatus('disconnected');
        this.socket = null;
      };
    } catch {
      this.setStatus('disconnected');
    }
  }

  public disconnect() {
    if (this.reconnectTimeout) {
      clearTimeout(this.reconnectTimeout);
      this.reconnectTimeout = null;
    }
    if (this.mockInterval) {
      clearInterval(this.mockInterval);
      this.mockInterval = null;
    }
    if (this.socket) {
      this.socket.onclose = null;
      this.socket.close();
      this.socket = null;
    }
    this.scanId = null;
    this.setStatus('disconnected');
  }

  private handleServerEvent(event: WsServerEvent) {
    this.eventListeners.forEach((listener) => {
      try {
        listener(event);
      } catch (e) {
        console.error('[WebSocket] Error in event listener:', e);
      }
    });

    switch (event.event) {
      case 'scan_progress':
        this.progressListeners.forEach((listener) => {
          try {
            listener(event.data);
          } catch (e) {
            console.error('[WebSocket] Error in progress listener:', e);
          }
        });
        break;

      case 'scan_completed':
        this.completedListeners.forEach((listener) => {
          try {
            listener(event.data);
          } catch (e) {
            console.error('[WebSocket] Error in completed listener:', e);
          }
        });
        break;

      case 'scan_failed':
        this.failedListeners.forEach((listener) => {
          try {
            listener(event.data);
          } catch (e) {
            console.error('[WebSocket] Error in failed listener:', e);
          }
        });
        break;
    }
  }

  /**
   * Realistic Mock Stream Simulator for testing UI progress bars,
   * live phase updates, alert counters, and completion events.
   */
  public startMockSimulation(
    scanId: string,
    appId = '11111111-1111-1111-1111-111111111111',
    initialPercent = 0
  ) {
    if (this.mockInterval) {
      clearInterval(this.mockInterval);
    }

    this.setStatus('connected');
    let percent = initialPercent;
    let alerts = 0;

    const phases = [
      { max: 15, status: 'queued' as ScanStatus, phase: 'Initializing scan engine & validating scope regexes' },
      { max: 40, status: 'spidering' as ScanStatus, phase: 'Spidering target paths & crawling interactive forms' },
      { max: 85, status: 'active_scanning' as ScanStatus, phase: 'Injecting active attack payloads (SQLi, XSS, SSRF, Deserialization)' },
      { max: 99, status: 'ingesting' as ScanStatus, phase: 'Ingesting ZAP findings & computing differential posture delta' },
    ];

    this.mockInterval = window.setInterval(() => {
      percent += Math.floor(Math.random() * 6) + 3;

      if (percent >= 100) {
        if (this.mockInterval) clearInterval(this.mockInterval);
        this.mockInterval = null;

        const completedEvent: WsServerEvent = {
          event: 'scan_completed',
          data: {
            scan_id: scanId,
            application_id: appId,
            severity_counts: {
              critical: 2,
              high: 3,
              medium: 4,
              low: 2,
              info: 1,
            },
            overall_risk_score: 78.4,
          },
        };
        this.handleServerEvent(completedEvent);
        return;
      }

      if (percent > 35 && Math.random() > 0.4) {
        alerts += Math.floor(Math.random() * 2) + 1;
      }

      const currentPhaseConfig =
        phases.find((p) => percent <= p.max) || phases[phases.length - 1];

      const progressEvent: WsServerEvent = {
        event: 'scan_progress',
        data: {
          scan_id: scanId,
          application_id: appId,
          status: currentPhaseConfig.status,
          progress_percent: percent,
          current_phase: currentPhaseConfig.phase,
          alerts_found_so_far: alerts,
        },
      };

      this.handleServerEvent(progressEvent);
    }, 1200);
  }

  // ============================================================================
  // Subscription Listeners (return unsubscribe cleanup functions)
  // ============================================================================

  public onStatusChange(listener: WsStatusListener): () => void {
    this.statusListeners.add(listener);
    listener(this.status);
    return () => this.statusListeners.delete(listener);
  }

  public onEvent(listener: WsEventListener): () => void {
    this.eventListeners.add(listener);
    return () => this.eventListeners.delete(listener);
  }

  public onScanProgress(listener: ScanProgressListener): () => void {
    this.progressListeners.add(listener);
    return () => this.progressListeners.delete(listener);
  }

  public onScanCompleted(listener: ScanCompletedListener): () => void {
    this.completedListeners.add(listener);
    return () => this.completedListeners.delete(listener);
  }

  public onScanFailed(listener: ScanFailedListener): () => void {
    this.failedListeners.add(listener);
    return () => this.failedListeners.delete(listener);
  }
}

export const wsClient = new ScanWebSocketClient();
export default wsClient;
