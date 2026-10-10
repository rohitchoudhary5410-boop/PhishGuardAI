import { useState, useEffect } from 'react';
import { Link, NavLink } from 'react-router-dom';
import { Shield, Sun, Moon, Menu, X } from 'lucide-react';
import { useTheme } from '../../context/ThemeContext';
import { useNav } from '../../context/NavContext';
import { checkApiHealth, IS_MOCK } from '../../services/api';
import './Navbar.css';

// Single source of truth for site navigation. `primary` marks the links that
// fit the desktop bar; the mobile menu renders all of them. Previously the two
// lists were maintained separately and /bulk-scanner appeared in neither the
// desktop bar nor the mobile menu, leaving it with no mobile entry point at all.
const NAV_LINKS = [
  { to: '/', label: 'Home', primary: true },
  { to: '/scanner', label: 'Scanner', primary: true },
  { to: '/device-scanner', label: 'Device Scanner', primary: true },
  { to: '/email-scanner', label: 'Gmail Shield', primary: true },
  { to: '/dashboard', label: 'Dashboard', primary: true },
  { to: '/history', label: 'History', primary: true },
  { to: '/analytics', label: 'Analytics', primary: false },
  { to: '/model-insights', label: 'Model Insights', primary: false },
  { to: '/bulk-scanner', label: 'Bulk Scanner', primary: false },
  { to: '/settings', label: 'Settings', primary: false },
];

const MOBILE_MENU_ID = 'navbar-mobile-menu';
const SIDEBAR_DRAWER_ID = 'dashboard-sidebar';

const linkClass = ({ isActive }) => `nav-link ${isActive ? 'active' : ''}`;

const Navbar = () => {
  const { theme, toggleTheme } = useTheme();
  const { isOpen, isDashboard, close, toggle } = useNav();
  const [apiStatus, setApiStatus] = useState('checking'); // 'checking', 'online', 'offline'

  const verifyHealth = async () => {
    setApiStatus('checking');
    try {
      const isHealthy = await checkApiHealth(true);
      setApiStatus(isHealthy ? 'online' : 'offline');
    } catch {
      setApiStatus('offline');
    }
  };

  useEffect(() => {
    let active = true;
    const runCheck = async () => {
      try {
        const isHealthy = await checkApiHealth();
        if (!active) return;
        setApiStatus(isHealthy ? 'online' : 'offline');
      } catch {
        if (!active) return;
        setApiStatus('offline');
      }
    };

    runCheck();
    const interval = setInterval(runCheck, 15000);

    return () => {
      active = false;
      clearInterval(interval);
    };
  }, []);

  // On app routes this same button drives the sidebar drawer, so it must point
  // aria-controls at whichever panel it actually opens.
  const controlsId = isDashboard ? SIDEBAR_DRAWER_ID : MOBILE_MENU_ID;

  return (
    <>
      <nav
        className={`navbar ${isDashboard ? 'navbar--app' : ''}`}
        id="main-navbar"
        aria-label="Main"
      >
        <div className="navbar-inner">
          <Link to="/" className="navbar-brand">
            <span className="navbar-logo" aria-hidden="true">
              <Shield size={18} />
            </span>
            <span className="navbar-title">
              Phish<span>Guard</span> AI
            </span>
          </Link>

          <div className="navbar-nav">
            {NAV_LINKS.filter((link) => link.primary).map((link) => (
              <NavLink key={link.to} to={link.to} className={linkClass} end={link.to === '/'}>
                {link.label}
              </NavLink>
            ))}
          </div>

          <div className="navbar-actions">
            <div 
              className={`api-status-badge ${apiStatus}`}
              onClick={verifyHealth}
              role="button"
              tabIndex={0}
              onKeyDown={(e) => e.key === 'Enter' && verifyHealth()}
              title={
                IS_MOCK 
                  ? 'API: Demo Mode (Mock data) — Click to refresh' 
                  : apiStatus === 'checking' 
                    ? 'Checking API connection...' 
                    : apiStatus === 'online' 
                      ? 'API Status: Live & Connected' 
                      : 'API Status: Disconnected — Click to retry'
              }
              aria-label={
                IS_MOCK
                  ? 'Demo Mode Active'
                  : `API Connection Status: ${apiStatus}`
              }
            >
              <span className="api-status-dot" />
              <span className="api-status-text">
                {IS_MOCK ? 'Demo' : apiStatus === 'checking' ? 'Connecting...' : apiStatus === 'online' ? 'Online' : 'Offline'}
              </span>
            </div>
            <button
              type="button"
              className="theme-toggle"
              onClick={toggleTheme}
              /* Names the outcome, not the widget — a static "Toggle theme"
                 never told the user which way it would go. */
              aria-label={theme === 'dark' ? 'Switch to light theme' : 'Switch to dark theme'}
              id="theme-toggle-btn"
            >
              {theme === 'dark' ? <Sun size={18} /> : <Moon size={18} />}
            </button>

            <Link to="/scanner" className="btn btn-primary btn-sm navbar-cta" id="nav-scan-btn">
              Scan URL
            </Link>

            <button
              type="button"
              className="mobile-menu-btn"
              onClick={toggle}
              aria-label={isOpen ? 'Close menu' : 'Open menu'}
              aria-expanded={isOpen}
              aria-controls={controlsId}
              id="mobile-menu-toggle"
            >
              {isOpen ? <X size={20} /> : <Menu size={20} />}
            </button>
          </div>
        </div>
      </nav>

      {/* Only rendered on marketing routes. On app routes the same trigger opens
          the sidebar drawer instead, which carries the grouped dashboard nav. */}
      {!isDashboard && (
        <div
          id={MOBILE_MENU_ID}
          className={`mobile-menu ${isOpen ? 'open' : ''}`}
          /* Keeps the closed panel's links out of the tab order while it stays
             in the DOM for the transition. */
          inert={!isOpen}
        >
          <nav className="mobile-menu-nav" aria-label="Site">
            {NAV_LINKS.map((link) => (
              <NavLink
                key={link.to}
                to={link.to}
                className={linkClass}
                end={link.to === '/'}
                onClick={close}
              >
                {link.label}
              </NavLink>
            ))}
          </nav>
        </div>
      )}
    </>
  );
};

export default Navbar;
