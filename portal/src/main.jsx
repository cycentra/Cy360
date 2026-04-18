import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import './styles/globals.css'   // ← replaces index.css + GLOBAL_CSS string in App.jsx
import App from './App.jsx'
import { GuestScanPage } from './pages/guest-scan/GuestScanPage.jsx'

// Route /guest-scan to the standalone guest page (no auth, no sidebar)
const isGuestScan = window.location.pathname.startsWith('/guest-scan')

createRoot(document.getElementById('root')).render(
  <StrictMode>
    {isGuestScan ? <GuestScanPage /> : <App />}
  </StrictMode>,
)
