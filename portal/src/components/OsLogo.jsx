/**
 * components/OsLogo.jsx
 * Official OS and brand SVG logo components used across CyCentra 360.
 * All paths sourced from official brand guidelines.
 */

/** Microsoft Windows 4-square logo (official brand colours) */
export function WindowsLogo({ size = 24 }) {
  return (
    <svg width={size} height={size} viewBox="0 0 23 23" xmlns="http://www.w3.org/2000/svg" aria-label="Windows">
      <path fill="#f25022" d="M1 1h10v10H1z"/>
      <path fill="#00a4ef" d="M12 1h10v10H12z"/>
      <path fill="#7fba00" d="M1 12h10v10H1z"/>
      <path fill="#ffb900" d="M12 12h10v10H12z"/>
    </svg>
  );
}

/** Apple logo (official monochrome shape) */
export function AppleLogo({ size = 24, color = "#ffffff" }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg" aria-label="macOS">
      <path fill={color} d="
        M18.71 19.5c-.83 1.24-1.71 2.45-3.05 2.47-1.34.03-1.77-.79-3.29-.79-1.53
        0-2 .77-3.27.82-1.31.05-2.3-1.32-3.14-2.53C4.25 17 2.94 12.45 4.7 9.39c.87-1.52
        2.43-2.48 4.12-2.51 1.28-.02 2.5.87 3.29.87.78 0 2.26-1.07 3.8-.91.65.03
        2.47.26 3.64 1.98l-.09.06c-.22.14-2.18 1.27-2.16 3.8.03 3.02 2.65 4.03
        2.68 4.04-.03.07-.42 1.44-1.38 2.84zM13 3.5c.73-.83 1.94-1.46 2.94-1.5.13
        1.17-.34 2.35-1.04 3.19-.69.85-1.83 1.51-2.95 1.42-.15-1.15.41-2.35 1.05-3.11z
      "/>
    </svg>
  );
}

/** Linux — Tux penguin (simplified official mascot) */
export function LinuxLogo({ size = 24 }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg" aria-label="Linux">
      {/* Body */}
      <ellipse cx="12" cy="14.5" rx="5.5" ry="6.5" fill="#2c2c2c"/>
      {/* White belly */}
      <ellipse cx="12" cy="15.5" rx="3.2" ry="4.8" fill="#f0f0f0"/>
      {/* Head */}
      <ellipse cx="12" cy="6.5" rx="4" ry="4" fill="#2c2c2c"/>
      {/* Left eye white */}
      <ellipse cx="10.3" cy="5.5" rx="1.1" ry="1.3" fill="#f0f0f0"/>
      {/* Right eye white */}
      <ellipse cx="13.7" cy="5.5" rx="1.1" ry="1.3" fill="#f0f0f0"/>
      {/* Left pupil */}
      <circle cx="10.3" cy="5.7" r="0.55" fill="#1a1a1a"/>
      {/* Right pupil */}
      <circle cx="13.7" cy="5.7" r="0.55" fill="#1a1a1a"/>
      {/* Beak */}
      <path d="M10.8 7.8 Q12 9 13.2 7.8 Q12 7.1 10.8 7.8Z" fill="#f5a623"/>
      {/* Left ear tuft */}
      <ellipse cx="9" cy="3.2" rx="1.2" ry="1.8" fill="#2c2c2c" transform="rotate(-15 9 3.2)"/>
      {/* Right ear tuft */}
      <ellipse cx="15" cy="3.2" rx="1.2" ry="1.8" fill="#2c2c2c" transform="rotate(15 15 3.2)"/>
      {/* Left foot */}
      <path d="M8 21 Q6 21.5 6.5 20 Q7.5 19 9.5 19.5 Q9 20.5 8 21Z" fill="#f5a623"/>
      {/* Right foot */}
      <path d="M16 21 Q18 21.5 17.5 20 Q16.5 19 14.5 19.5 Q15 20.5 16 21Z" fill="#f5a623"/>
    </svg>
  );
}

/** CyCentra 360 brand logo — CY monogram with gradient */
export function CyCentraLogo({ width = 120, height = 40 }) {
  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      width={width}
      height={height}
      viewBox="0 0 600 200"
      aria-label="CyCentra 360"
    >
      <defs>
        <linearGradient id="cyLogoGrad" x1="0%" y1="0%" x2="100%" y2="0%">
          <stop offset="0%"   stop-color="#0B1F3A"/>
          <stop offset="40%"  stop-color="#1E40FF"/>
          <stop offset="100%" stop-color="#4FB6FF"/>
        </linearGradient>
      </defs>
      {/* C letter */}
      <g fill="url(#cyLogoGrad)">
        <path d="
          M120 20 H60
          C18 20 0 38 0 80
          V120
          C0 162 18 180 60 180
          H120
          V153
          H70
          C48 153 35 140 35 118
          V82
          C35 60 48 47 70 47
          H120 Z
        "/>
        {/* Y letter */}
        <path d="
          M140 20 H168
          V85
          L198 140
          V180
          H168
          V148
          L140 95 Z
        "/>
        {/* Y right arm */}
        <path d="
          M198 20 H226
          V95
          L198 140
          V85
          L226 35
          V20 Z
        "/>
      </g>
      {/* Divider */}
      <rect x="248" y="30" width="2" height="140" fill="#4FB6FF" opacity="0.4"/>
      {/* CYCENTRA text */}
      <text
        x="268" y="108"
        fontFamily="Helvetica Neue, Arial, sans-serif"
        fontSize="52"
        fontWeight="700"
        letterSpacing="4"
        fill="#e8eaf0"
      >CYCENTRA</text>
      {/* 360 sub-text */}
      <text
        x="270" y="145"
        fontFamily="Helvetica Neue, Arial, sans-serif"
        fontSize="18"
        letterSpacing="8"
        fill="#4FB6FF"
        opacity="0.8"
      >360</text>
    </svg>
  );
}

/** CyCentra EDR badge — compact version for installer splash */
export function CyCentraEDRBadge({ width = 200, height = 56 }) {
  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      width={width}
      height={height}
      viewBox="0 0 400 112"
      aria-label="CyCentra CyEDR"
    >
      <defs>
        <linearGradient id="edrGrad" x1="0%" y1="0%" x2="100%" y2="0%">
          <stop offset="0%"   stopColor="#1E40FF"/>
          <stop offset="100%" stopColor="#4FB6FF"/>
        </linearGradient>
      </defs>
      {/* Shield shape background */}
      <path
        d="M40 8 L72 8 L72 60 L56 80 L40 60 Z"
        fill="none" stroke="url(#edrGrad)" strokeWidth="3"
        opacity="0.7"
      />
      {/* CY inside shield */}
      <text x="44" y="48" fontFamily="monospace" fontSize="20" fontWeight="900"
            fill="url(#edrGrad)">CY</text>
      {/* EDR label */}
      <text x="86" y="38" fontFamily="Helvetica Neue, Arial, sans-serif"
            fontSize="26" fontWeight="800" fill="#e8eaf0">CyEDR</text>
      <text x="88" y="62" fontFamily="Helvetica Neue, Arial, sans-serif"
            fontSize="14" letterSpacing="3" fill="#4FB6FF" opacity="0.75">
        ENDPOINT DEFENSE
      </text>
    </svg>
  );
}
