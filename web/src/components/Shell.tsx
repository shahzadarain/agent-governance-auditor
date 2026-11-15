// SPDX-License-Identifier: Apache-2.0

import { useEffect, useRef, useState } from "react";
import { NavLink, Outlet, useLocation } from "react-router-dom";
import { useAuth } from "../auth";
import { DISCLAIMER, projectRoleLabel } from "../lib/labels";
import { effectiveTheme, saveTheme, storedTheme, type ThemeChoice } from "../lib/theme";
import {
  IconClose,
  IconFolder,
  IconGrid,
  IconHome,
  IconList,
  IconLogout,
  IconMenu,
  IconMoon,
  IconPlug,
  IconSliders,
  IconSun,
  IconUsers,
  Logo,
} from "./Icons";

export function ThemeToggle() {
  const [choice, setChoice] = useState<ThemeChoice>(() => storedTheme());
  const current = effectiveTheme(choice);
  const next = current === "dark" ? "light" : "dark";
  return (
    <button
      type="button"
      className="icon-btn"
      onClick={() => {
        saveTheme(next);
        setChoice(next);
      }}
      aria-label={`Switch to ${next} theme`}
      title={`Switch to ${next} theme`}
    >
      {current === "dark" ? <IconSun size={20} /> : <IconMoon size={20} />}
    </button>
  );
}

export function Brand({ compact }: { compact?: boolean }) {
  return (
    <span className="brand">
      <Logo size={compact ? 30 : 36} />
      <span className="brand-text">
        <span className="brand-name">AgentGov</span>
        <span className="brand-sub">Auditor</span>
      </span>
    </span>
  );
}

export function Footer() {
  const { version } = useAuth();
  return (
    <footer className="app-footer">
      <span>{DISCLAIMER}</span>
      {version && <span className="muted">Server {version.version}</span>}
    </footer>
  );
}

export function Shell() {
  const { user, isAdmin, signOut } = useAuth();
  const [open, setOpen] = useState(false);
  const location = useLocation();
  const mainRef = useRef<HTMLElement>(null);

  // Close the mobile menu and move focus to the page on navigation.
  useEffect(() => {
    setOpen(false);
    mainRef.current?.focus({ preventScroll: true });
    window.scrollTo(0, 0);
  }, [location.pathname]);

  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") setOpen(false);
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open]);

  const link = ({ isActive }: { isActive: boolean }) => `nav-link${isActive ? " active" : ""}`;

  return (
    <div className={`app${open ? " nav-open" : ""}`}>
      <a href="#main" className="skip-link">
        Skip to content
      </a>
      <aside className="sidebar" aria-label="Main">
        <div className="sidebar-head">
          <NavLink to="/" className="brand-link" aria-label="AgentGov Auditor, overview">
            <Brand />
          </NavLink>
          <button type="button" className="icon-btn sidebar-close" onClick={() => setOpen(false)} aria-label="Close menu">
            <IconClose size={20} />
          </button>
        </div>
        <nav aria-label="Main">
          <p className="nav-group">Assess</p>
          <ul>
            <li>
              <NavLink to="/" end className={link}>
                <IconHome size={18} />
                Overview
              </NavLink>
            </li>
            <li>
              <NavLink to="/projects" className={link}>
                <IconFolder size={18} />
                Projects
              </NavLink>
            </li>
            <li>
              <NavLink to="/connect" className={link}>
                <IconPlug size={18} />
                Connect a repository
              </NavLink>
            </li>
          </ul>
          <p className="nav-group">Reference</p>
          <ul>
            <li>
              <NavLink to="/controls" className={link}>
                <IconGrid size={18} />
                Controls catalog
              </NavLink>
            </li>
            <li>
              <NavLink to="/policies" className={link}>
                <IconSliders size={18} />
                Policies and profiles
              </NavLink>
            </li>
          </ul>
          <p className="nav-group">Administer</p>
          <ul>
            <li>
              <NavLink to="/audit" className={link}>
                <IconList size={18} />
                Audit events
              </NavLink>
            </li>
            {isAdmin && (
              <li>
                <NavLink to="/users" className={link}>
                  <IconUsers size={18} />
                  Users
                </NavLink>
              </li>
            )}
          </ul>
        </nav>
        <p className="sidebar-foot">Static scans are read-only and offline. The dashboard shows only what was uploaded.</p>
      </aside>
      <div className="scrim" onClick={() => setOpen(false)} aria-hidden="true" />

      <div className="app-main">
        <header className="topbar">
          <button
            type="button"
            className="icon-btn menu-btn"
            onClick={() => setOpen(true)}
            aria-label="Open menu"
            aria-expanded={open}
          >
            <IconMenu size={22} />
          </button>
          <span className="topbar-brand">
            <Brand compact />
          </span>
          <div className="topbar-spacer" />
          <ThemeToggle />
          {user && (
            <div className="user-box">
              <span className="avatar" aria-hidden="true">
                {user.username.slice(0, 1).toUpperCase()}
              </span>
              <span className="user-text">
                <span className="user-name" data-testid="user-name">
                  {user.username}
                </span>
                <span className="user-role">{projectRoleLabel(user.role)}</span>
              </span>
            </div>
          )}
          <button type="button" className="btn btn-ghost" onClick={() => void signOut()} aria-label="Sign out">
            <IconLogout size={18} />
            <span className="hide-sm">Sign out</span>
          </button>
        </header>
        <main id="main" ref={mainRef} tabIndex={-1} className="content">
          <Outlet />
        </main>
        <Footer />
      </div>
    </div>
  );
}
