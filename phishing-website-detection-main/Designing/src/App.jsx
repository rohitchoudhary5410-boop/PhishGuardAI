import { useEffect, lazy, Suspense } from 'react';
import { Routes, Route, useLocation } from 'react-router-dom';
import Navbar from './components/Navbar/Navbar';
import Footer from './components/Footer/Footer';
import DashboardLayout from './components/Layout/DashboardLayout';
import BackToTop from './components/BackToTop/BackToTop';
import { ToastProvider } from './components/Toast/Toast';
import { ThemeProvider } from './context/ThemeContext';
import { NavProvider } from './context/NavContext';
import './App.css';

// Code-split pages for ultra-fast initial load & smooth tab transitions
const Home = lazy(() => import('./pages/Home/Home'));
const Scanner = lazy(() => import('./pages/Scanner/Scanner'));
const Dashboard = lazy(() => import('./pages/Dashboard/Dashboard'));
const DeviceScanner = lazy(() => import('./pages/DeviceScanner/DeviceScanner'));
const EmailScanner = lazy(() => import('./pages/EmailScanner/EmailScanner'));
const Analytics = lazy(() => import('./pages/Analytics/Analytics'));
const ModelInsights = lazy(() => import('./pages/ModelInsights/ModelInsights'));
const BulkScanner = lazy(() => import('./pages/BulkScanner/BulkScanner'));
const History = lazy(() => import('./pages/History/History'));
const Settings = lazy(() => import('./pages/Settings/Settings'));

// Smooth top loader & skeleton fallback for page transitions
const PageLoadingFallback = () => (
  <>
    <div className="page-top-loader" aria-hidden="true" />
    <div className="page-fallback-container">
      <div className="page-fallback-skeleton">
        <div className="skeleton-box" style={{ height: '36px', width: '38%' }} />
        <div className="skeleton-box" style={{ height: '20px', width: '60%' }} />
        <div className="skeleton-box" style={{ height: '240px', width: '100%', marginTop: '1rem' }} />
      </div>
    </div>
  </>
);

// Routes that render inside DashboardLayout, hiding the marketing footer.
const DASHBOARD_ROUTES = [
  '/dashboard',
  '/device-scanner',
  '/analytics',
  '/model-insights',
  '/email-scanner',
  '/bulk-scanner',
  '/history',
  '/settings',
];

const AppShell = () => {
  const location = useLocation();
  const isDashboard = DASHBOARD_ROUTES.some((path) => location.pathname.startsWith(path));

  // Reset scroll on navigation with instant behavior
  useEffect(() => {
    window.scrollTo({ top: 0, left: 0, behavior: 'instant' });
  }, [location.pathname]);

  return (
    <NavProvider>
      <div className="app-container">
        <a className="skip-link" href="#main-content">
          Skip to main content
        </a>

        <Navbar />

        <main className="app-main" id="main-content">
          <Suspense fallback={<PageLoadingFallback />}>
            <Routes>
              {/* Public */}
              <Route path="/" element={<Home />} />
              <Route path="/scanner" element={<Scanner />} />

              {/* Dashboard (with sidebar) */}
              <Route element={<DashboardLayout />}>
                <Route path="/dashboard" element={<Dashboard />} />
                <Route path="/device-scanner" element={<DeviceScanner />} />
                <Route path="/email-scanner" element={<EmailScanner />} />
                <Route path="/analytics" element={<Analytics />} />
                <Route path="/model-insights" element={<ModelInsights />} />
                <Route path="/bulk-scanner" element={<BulkScanner />} />
                <Route path="/history" element={<History />} />
                <Route path="/settings" element={<Settings />} />
              </Route>
            </Routes>
          </Suspense>
        </main>

        {!isDashboard && <Footer />}

        <BackToTop />
      </div>
    </NavProvider>
  );
};

const App = () => (
  <ThemeProvider>
    <ToastProvider>
      <AppShell />
    </ToastProvider>
  </ThemeProvider>
);

export default App;
