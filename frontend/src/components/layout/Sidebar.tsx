import React from 'react';
import {
  LayoutDashboard,
  Layers,
  Activity,
  ShieldAlert,
  FileText,
  Shield,
  Database,
  User,
} from 'lucide-react';
import { UserProfile } from '../../types';

export type NavTab = 'dashboard' | 'apps' | 'scans' | 'vulns' | 'reports';

export interface SidebarProps {
  activeTab: NavTab;
  onTabChange: (tab: NavTab) => void;
  mockMode: boolean;
  onToggleMockMode: () => void;
  openVulnsCount?: number;
  activeScansCount?: number;
  userProfile?: UserProfile | null;
}

export const Sidebar: React.FC<SidebarProps> = ({
  activeTab,
  onTabChange,
  mockMode,
  onToggleMockMode,
  openVulnsCount = 0,
  activeScansCount = 0,
  userProfile = null,
}) => {
  const navItems: Array<{
    id: NavTab;
    label: string;
    icon: React.ReactNode;
    badge?: number | null;
    badgeStyle?: string;
  }> = [
    {
      id: 'dashboard',
      label: 'Dashboard',
      icon: <LayoutDashboard size={18} />,
    },
    {
      id: 'apps',
      label: 'Applications',
      icon: <Layers size={18} />,
    },
    {
      id: 'scans',
      label: 'Scans',
      icon: <Activity size={18} />,
      badge: activeScansCount > 0 ? activeScansCount : null,
      badgeStyle: 'nav-badge-pulse',
    },
    {
      id: 'vulns',
      label: 'Vulnerabilities',
      icon: <ShieldAlert size={18} />,
      badge: openVulnsCount > 0 ? openVulnsCount : null,
      badgeStyle: 'nav-badge-rose',
    },
    {
      id: 'reports',
      label: 'Reports',
      icon: <FileText size={18} />,
    },
  ];

  return (
    <aside className="sidebar">
      {/* Brand Header */}
      <div className="sidebar-brand">
        <div className="brand-icon-wrapper">
          <Shield size={20} className="brand-icon" />
        </div>
        <div className="brand-info">
          <div className="brand-title">KDS AppSec</div>
          <div className="brand-subtitle">VMP Workbench</div>
        </div>
        <div className="brand-version">v1.0</div>
      </div>

      {/* Navigation Links */}
      <nav className="sidebar-nav">
        <div className="nav-section-title">PLATFORM</div>
        {navItems.map((item) => {
          const isActive = activeTab === item.id;
          return (
            <button
              key={item.id}
              onClick={() => onTabChange(item.id)}
              className={`nav-item ${isActive ? 'nav-item-active' : ''}`}
              type="button"
            >
              <span className="nav-icon">{item.icon}</span>
              <span className="nav-label">{item.label}</span>
              {item.badge !== null && item.badge !== undefined && (
                <span className={`nav-badge ${item.badgeStyle || ''}`}>
                  {item.badge}
                </span>
              )}
            </button>
          );
        })}
      </nav>

      {/* Footer Controls */}
      <div className="sidebar-footer">
        {/* Mock Mode Switch */}
        <div className="mock-toggle-box">
          <div className="mock-toggle-info">
            <div className="mock-toggle-label">
              <Database size={13} className="text-slate-500" />
              <span>Offline Mock</span>
            </div>
            <div className="mock-toggle-desc">
              {mockMode ? 'Simulated data active' : 'Live REST & WS'}
            </div>
          </div>
          <button
            type="button"
            onClick={onToggleMockMode}
            className={`toggle-switch ${mockMode ? 'toggle-active' : ''}`}
            aria-label="Toggle Mock Mode"
            title={mockMode ? 'Switch to live backend' : 'Switch to standalone mock'}
          >
            <span className="toggle-slider" />
          </button>
        </div>

        {/* User Card */}
        <div className="sidebar-user">
          <div className="user-avatar">
            <User size={15} />
          </div>
          <div className="user-details">
            <div className="user-name">{userProfile?.email || 'admin@kds.local'}</div>
            <div className="user-role">
              {userProfile?.role ? userProfile.role.replace('_', ' ').toUpperCase() : 'Administrator'}
            </div>
          </div>
          <div className="user-status-dot" title="Authenticated session active" />
        </div>
      </div>
    </aside>
  );
};
