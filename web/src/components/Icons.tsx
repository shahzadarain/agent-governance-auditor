// SPDX-License-Identifier: Apache-2.0
//
// Small inline SVG icons. Every icon is decorative (aria-hidden); the text
// label next to it carries the meaning.

import type { ReactNode, SVGProps } from "react";
import type { DecisionKey, Rollup } from "../lib/labels";

type P = { size?: number } & Omit<SVGProps<SVGSVGElement>, "children">;

function Svg({ size = 20, children, ...rest }: P & { children: ReactNode }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={2}
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      focusable="false"
      {...rest}
    >
      {children}
    </svg>
  );
}

export const IconCheckCircle = (p: P) => (
  <Svg {...p}>
    <circle cx="12" cy="12" r="9" />
    <path d="M8 12.5l2.8 2.8L16 9.5" />
  </Svg>
);
export const IconHalfCircle = (p: P) => (
  <Svg {...p}>
    <circle cx="12" cy="12" r="9" />
    <path d="M12 3a9 9 0 0 0 0 18z" fill="currentColor" stroke="none" />
  </Svg>
);
export const IconQuestion = (p: P) => (
  <Svg {...p}>
    <path d="M12 2.8l9.2 9.2-9.2 9.2L2.8 12z" />
    <path d="M9.9 10a2.2 2.2 0 1 1 3.2 2c-.7.4-1.1.9-1.1 1.6" />
    <path d="M12 16.4v.1" />
  </Svg>
);
export const IconStop = (p: P) => (
  <Svg {...p}>
    <path d="M8.3 3h7.4L21 8.3v7.4L15.7 21H8.3L3 15.7V8.3z" />
    <path d="M9 9l6 6M15 9l-6 6" />
  </Svg>
);
export const IconDash = (p: P) => (
  <Svg {...p}>
    <circle cx="12" cy="12" r="9" strokeDasharray="3 3" />
    <path d="M8.5 12h7" />
  </Svg>
);
export const IconWarning = (p: P) => (
  <Svg {...p}>
    <path d="M12 3.5l9.5 16.5h-19z" />
    <path d="M12 10v4.5M12 17.2v.1" />
  </Svg>
);
export const IconShieldCheck = (p: P) => (
  <Svg {...p}>
    <path d="M12 2.8l7.5 3v6c0 4.6-3.1 7.7-7.5 9.4-4.4-1.7-7.5-4.8-7.5-9.4v-6z" />
    <path d="M8.6 12.2l2.4 2.5 4.5-5.2" />
  </Svg>
);
export const IconLock = (p: P) => (
  <Svg {...p}>
    <rect x="5" y="11" width="14" height="9" rx="2" />
    <path d="M8 11V8a4 4 0 0 1 8 0v3" />
  </Svg>
);
export const IconHome = (p: P) => (
  <Svg {...p}>
    <path d="M3.5 11.5L12 4l8.5 7.5" />
    <path d="M5.5 10v9.5h13V10" />
  </Svg>
);
export const IconFolder = (p: P) => (
  <Svg {...p}>
    <path d="M3 7.5a2 2 0 0 1 2-2h4l2 2.5h8a2 2 0 0 1 2 2v7.5a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z" />
  </Svg>
);
export const IconGrid = (p: P) => (
  <Svg {...p}>
    <rect x="3.5" y="3.5" width="7" height="7" rx="1.5" />
    <rect x="13.5" y="3.5" width="7" height="7" rx="1.5" />
    <rect x="3.5" y="13.5" width="7" height="7" rx="1.5" />
    <rect x="13.5" y="13.5" width="7" height="7" rx="1.5" />
  </Svg>
);
export const IconSliders = (p: P) => (
  <Svg {...p}>
    <path d="M4 7h10M18 7h2M4 17h2M10 17h10" />
    <circle cx="16" cy="7" r="2" />
    <circle cx="8" cy="17" r="2" />
  </Svg>
);
export const IconList = (p: P) => (
  <Svg {...p}>
    <path d="M8 6h12M8 12h12M8 18h12M4 6v.1M4 12v.1M4 18v.1" />
  </Svg>
);
export const IconPlug = (p: P) => (
  <Svg {...p}>
    <path d="M9 3v5M15 3v5M6.5 8h11v3.5a5.5 5.5 0 0 1-11 0zM12 17v4" />
  </Svg>
);
export const IconUsers = (p: P) => (
  <Svg {...p}>
    <circle cx="9" cy="8.5" r="3.5" />
    <path d="M2.5 20c.500-3.5 3-5.5 6.5-5.5s6 2 6.5 5.5M16 5.2a3.5 3.5 0 0 1 0 6.6M18.5 14.8c1.7.700 2.7 2.4 3 5.2" />
  </Svg>
);
export const IconSun = (p: P) => (
  <Svg {...p}>
    <circle cx="12" cy="12" r="4" />
    <path d="M12 2.5v2M12 19.5v2M2.5 12h2M19.5 12h2M5.3 5.3l1.4 1.4M17.3 17.3l1.4 1.4M5.3 18.7l1.4-1.4M17.3 6.7l1.4-1.4" />
  </Svg>
);
export const IconMoon = (p: P) => (
  <Svg {...p}>
    <path d="M20 14.5A8.5 8.5 0 0 1 9.5 4 8.5 8.5 0 1 0 20 14.5z" />
  </Svg>
);
export const IconMenu = (p: P) => (
  <Svg {...p}>
    <path d="M4 6.5h16M4 12h16M4 17.5h16" />
  </Svg>
);
export const IconClose = (p: P) => (
  <Svg {...p}>
    <path d="M6 6l12 12M18 6L6 18" />
  </Svg>
);
export const IconCopy = (p: P) => (
  <Svg {...p}>
    <rect x="8.5" y="8.5" width="11" height="11" rx="2" />
    <path d="M15.5 8.5V6.5a2 2 0 0 0-2-2h-7a2 2 0 0 0-2 2v7a2 2 0 0 0 2 2h2" />
  </Svg>
);
export const IconCheck = (p: P) => (
  <Svg {...p}>
    <path d="M5 12.5l4.5 4.5L19 7.5" />
  </Svg>
);
export const IconChevronRight = (p: P) => (
  <Svg {...p}>
    <path d="M9 5.5l6.5 6.5L9 18.5" />
  </Svg>
);
export const IconArrowRight = (p: P) => (
  <Svg {...p}>
    <path d="M4.5 12h15M13.5 6l6 6-6 6" />
  </Svg>
);
export const IconRefresh = (p: P) => (
  <Svg {...p}>
    <path d="M20 5v5h-5M4 19v-5h5" />
    <path d="M19.5 10A8 8 0 0 0 5.6 7.5M4.5 14a8 8 0 0 0 13.9 2.5" />
  </Svg>
);
export const IconEye = (p: P) => (
  <Svg {...p}>
    <path d="M2.5 12S6 5.5 12 5.5 21.5 12 21.5 12 18 18.5 12 18.5 2.5 12 2.5 12z" />
    <circle cx="12" cy="12" r="3" />
  </Svg>
);
export const IconEyeOff = (p: P) => (
  <Svg {...p}>
    <path d="M4 4l16 16M9.9 5.8A9 9 0 0 1 12 5.5c6 0 9.5 6.5 9.5 6.5a17 17 0 0 1-2.7 3.5M6.2 7.3A16 16 0 0 0 2.5 12S6 18.5 12 18.5a9 9 0 0 0 4-1" />
    <path d="M9.9 9.9a3 3 0 0 0 4.2 4.2" />
  </Svg>
);
export const IconLogout = (p: P) => (
  <Svg {...p}>
    <path d="M14 4.5h3.5a2 2 0 0 1 2 2v11a2 2 0 0 1-2 2H14M10 8l-4 4 4 4M6 12h10" />
  </Svg>
);
export const IconClock = (p: P) => (
  <Svg {...p}>
    <circle cx="12" cy="12" r="9" />
    <path d="M12 7v5.5l3.5 2" />
  </Svg>
);
export const IconFile = (p: P) => (
  <Svg {...p}>
    <path d="M6.5 3h7.5l4.5 4.5V19a2 2 0 0 1-2 2h-10a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2z" />
    <path d="M14 3v4.5h4.5" />
  </Svg>
);
export const IconCompare = (p: P) => (
  <Svg {...p}>
    <path d="M7 4v16M17 4v16M3.5 8L7 4.5 10.5 8M13.5 16l3.5 3.5 3.5-3.5" />
  </Svg>
);
export const IconSearch = (p: P) => (
  <Svg {...p}>
    <circle cx="11" cy="11" r="6.5" />
    <path d="M16 16l4.5 4.5" />
  </Svg>
);
export const IconExternal = (p: P) => (
  <Svg {...p}>
    <path d="M13.5 4.5h6v6M19 5l-8.5 8.5M17.5 13.5V18a1.5 1.5 0 0 1-1.5 1.5H6A1.5 1.5 0 0 1 4.5 18V8A1.5 1.5 0 0 1 6 6.5h4.5" />
  </Svg>
);
export const IconPlus = (p: P) => (
  <Svg {...p}>
    <path d="M12 5v14M5 12h14" />
  </Svg>
);
export const IconInfo = (p: P) => (
  <Svg {...p}>
    <circle cx="12" cy="12" r="9" />
    <path d="M12 11v5.5M12 7.6v.1" />
  </Svg>
);

/** Severity as four bars; more filled bars mean a more serious finding. */
export function IconSeverity({ level, size = 16 }: { level: number; size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 16 16" aria-hidden="true" focusable="false">
      {[0, 1, 2, 3].map((i) => (
        <rect
          key={i}
          x={1 + i * 4}
          y={11 - i * 3}
          width={2.6}
          height={4 + i * 3}
          rx={0.8}
          fill="currentColor"
          opacity={i < level ? 1 : 0.25}
        />
      ))}
    </svg>
  );
}

export function RollupIcon({ rollup, size }: { rollup: Rollup; size?: number }) {
  switch (rollup) {
    case "verified":
      return <IconCheckCircle size={size} />;
    case "partial":
      return <IconHalfCircle size={size} />;
    case "failed":
      return <IconStop size={size} />;
    case "na":
      return <IconDash size={size} />;
    default:
      return <IconQuestion size={size} />;
  }
}

export function DecisionIcon({ decision, size }: { decision: DecisionKey; size?: number }) {
  switch (decision) {
    case "allow":
      return <IconShieldCheck size={size} />;
    case "block":
      return <IconStop size={size} />;
    case "review":
      return <IconWarning size={size} />;
    default:
      return <IconQuestion size={size} />;
  }
}

/** The product mark: three agent nodes joined to a shield with a check. */
export function Logo({ size = 32 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 128 128" aria-hidden="true" focusable="false">
      <rect x="3" y="3" width="122" height="122" rx="26" fill="#0B1220" stroke="#3B82F6" strokeWidth="3" />
      <g fill="none" stroke="#3B82F6" strokeWidth="3" strokeLinecap="round">
        <line x1="24" y1="40" x2="24" y2="88" />
        <line x1="24" y1="40" x2="48" y2="52" />
        <line x1="24" y1="88" x2="49" y2="78" />
      </g>
      <circle cx="24" cy="40" r="7" fill="#3B82F6" />
      <circle cx="24" cy="88" r="7" fill="#0B1220" stroke="#3B82F6" strokeWidth="3" />
      <path
        d="M76 22 L104 33 V62 C104 84 92 98 76 106 C60 98 48 84 48 62 V33 Z"
        fill="#0F1B33"
        stroke="#06B6D4"
        strokeWidth="4"
        strokeLinejoin="round"
      />
      <path d="M62 63 L72 74 L91 51" fill="none" stroke="#06B6D4" strokeWidth="6" strokeLinecap="round" strokeLinejoin="round" />
      <circle cx="48" cy="52" r="4" fill="#06B6D4" />
      <circle cx="49" cy="78" r="4" fill="#06B6D4" />
    </svg>
  );
}
