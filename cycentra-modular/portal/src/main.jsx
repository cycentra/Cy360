import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import './styles/globals.css'   // ← replaces index.css + GLOBAL_CSS string in App.jsx
import App from './App.jsx'

createRoot(document.getElementById('root')).render(
  <StrictMode>
    <App />
  </StrictMode>,
)
