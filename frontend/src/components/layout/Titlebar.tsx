import React, { useState } from 'react';
import {
  Bell,
  RefreshCw,
  Plus,
  Play,
  CheckCircle2,
  AlertTriangle,
  Info,
  X,
  Radio,
} from 'lucide-react';
import { NavTab } from './Sidebar';
import { WsConnectionStatus } from '../../services/websocket';

export interface NotificationItem {
  id: string;
  type: 'info' | 'success' | 'warning' | 'error';
  title: string;
  message: string;
  time: string;
  read?: boolean;
}

export interface TitlebarProps {
  activeTab: NavTab;
  wsStatus: WsConnectionStatus;
  notifications: NotificationItem[];
  onClearNotifications: () => void;
  onOpenTriggerScan: () => void;
  onOpenRegisterApp: () => void;
  onRefreshData: () => void;
  isRefreshing?: boolean;
}

export const Titlebar: React.FC<TitlebarProps> = ({
  activeTab,
  wsStatus,
  notifications,
  onClearNotifications,
  onOpenTriggerScan,
  onOpenRegisterApp,
  onRefreshData,
  isRefreshing = false,
}) => {
  const [showNotifications, setShowNotifications] = useState(false);

  const titles: Record<NavTab, { title: string; subtitle: string }> = {
    dashboard: {
      title: 'Executive Security Dashboard',
      subtitle: 'Global risk posture, OWASP Top 10 breakdown & SLA tracking',
    },
    apps: {
      title: 'Target Application Inventory',
      subtitle: 'Authorized web properties, scope boundaries & authentication profiles',
    },
    scans: {
      title: 'Security Assessments & Scans',
      subtitle: 'Active ZAP scanning pipeline, execution history & N vs N-1 diffs',
    },
    vulns: {
      title: 'Vulnerability Management & Triage',
      subtitle: 'Comprehensive findings triage, evidence inspection & remediation audit trail',
    },
    reports: {
      title: 'Executive & Compliance Reporting',
      subtitle: 'Typst-compiled PDF security attestations & structured JSON data exports',
    },
  };

  const current = titles[activeTab];
  const unreadCount = notifications.filter((n) => !n.read).length;

  const getWsStatusConfig = (status: WsConnectionStatus) => {
    switch (status) {
      case 'connected':
        return {
          dotClass: 'status-dot-green',
          text: 'Socket Live',
          textColor: 'text-emerald-700',
        };
      case 'connecting':
        return {
          dotClass: 'status-dot-amber animate-pulse',
          text: 'Syncing...',
          textColor: 'text-amber-700',
        };
      case 'error':
        return {
          dotClass: 'status-dot-rose',
          text: 'Socket Disconnected',
          textColor: 'text-rose-700',
        };
      default:
        return {
          dotClass: 'status-dot-slate',
          text: 'Socket Offline',
          textColor: 'text-slate-600',
        };
    }
  };

  const wsConfig = getWsStatusConfig(wsStatus);

  return (
    <header className="titlebar">
      {/* Breadcrumb & Title */}
      <div className="titlebar-info">
        <div className="titlebar-breadcrumb">
          <span className="text-slate-400">Workbench</span>
          <span className="breadcrumb-separator">/</span>
          <span className="font-medium text-slate-800 capitalize">{activeTab}</span>
        </div>
        <h1 className="titlebar-heading">{current.title}</h1>
      </div>

      {/* Action Controls & Indicators */}
      <div className="titlebar-actions">
        {/* WebSocket Status Indicator */}
        <div
          className="socket-indicator"
          title={`WebSocket Real-time status: ${wsStatus}`}
        >
          <span className={`status-dot ${wsConfig.dotClass}`} />
          <span className={`socket-text ${wsConfig.textColor}`}>
            {wsConfig.text}
          </span>
        </div>

        {/* Refresh Button */}
        <button
          type="button"
          onClick={onRefreshData}
          disabled={isRefreshing}
          className="btn-icon"
          title="Refresh current view"
        >
          <RefreshCw size={15} className={isRefreshing ? 'animate-spin' : ''} />
        </button>

        {/* Notifications Dropdown Trigger */}
        <div className="relative">
          <button
            type="button"
            onClick={() => setShowNotifications(!showNotifications)}
            className={`btn-icon ${unreadCount > 0 ? 'text-slate-900' : 'text-slate-500'}`}
            title="Real-time alert notifications"
          >
            <Bell size={16} />
            {unreadCount > 0 && (
              <span className="notification-badge">{unreadCount}</span>
            )}
          </button>

          {/* Notifications Flyout */}
          {showNotifications && (
            <div className="notifications-popover">
              <div className="popover-header">
                <span className="popover-title">Live Event Stream</span>
                <div className="flex items-center gap-2">
                  {notifications.length > 0 && (
                    <button
                      type="button"
                      onClick={onClearNotifications}
                      className="text-xs text-slate-500 hover:text-slate-800"
                    >
                      Clear
                    </button>
                  )}
                  <button
                    type="button"
                    onClick={() => setShowNotifications(false)}
                    className="text-slate-400 hover:text-slate-600"
                  >
                    <X size={14} />
                  </button>
                </div>
              </div>

              <div className="popover-body">
                {notifications.length === 0 ? (
                  <div className="empty-notifications">
                    <Radio size={20} className="text-slate-300 mb-1" />
                    <span>No unread notifications</span>
                  </div>
                ) : (
                  <div className="notifications-list">
                    {notifications.map((item) => (
                      <div key={item.id} className="notification-item">
                        <div className="notification-icon">
                          {item.type === 'error' && (
                            <AlertTriangle size={14} className="text-rose-600" />
                          )}
                          {item.type === 'warning' && (
                            <AlertTriangle size={14} className="text-amber-600" />
                          )}
                          {item.type === 'success' && (
                            <CheckCircle2 size={14} className="text-emerald-600" />
                          )}
                          {item.type === 'info' && (
                            <Info size={14} className="text-blue-600" />
                          )}
                        </div>
                        <div className="notification-content">
                          <div className="notification-item-title">{item.title}</div>
                          <div className="notification-item-msg">{item.message}</div>
                          <div className="notification-item-time">{item.time}</div>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          )}
        </div>

        {/* Primary Action Buttons */}
        <button
          type="button"
          onClick={onOpenRegisterApp}
          className="btn btn-secondary"
        >
          <Plus size={14} />
          <span>Register Target</span>
        </button>

        <button
          type="button"
          onClick={onOpenTriggerScan}
          className="btn btn-primary"
        >
          <Play size={14} />
          <span>Launch Scan</span>
        </button>
      </div>
    </header>
  );
};
