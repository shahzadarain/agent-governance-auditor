// SPDX-License-Identifier: Apache-2.0

import { useEffect, type ReactNode } from "react";
import { DISCLAIMER } from "../lib/labels";
import { IconCheckCircle } from "./Icons";
import { Brand, ThemeToggle } from "./Shell";

export function AuthLayout({ title, lead, children }: { title: string; lead: ReactNode; children: ReactNode }) {
  useEffect(() => {
    document.title = `${title} · AgentGov Auditor`;
  }, [title]);
  return (
    <div className="auth">
      <aside className="auth-side">
        <Brand />
        <div className="auth-pitch">
          <p className="auth-tagline">Know which AI agents are ready for release, and why.</p>
          <ul>
            <li>
              <IconCheckCircle size={18} />
              <span>24 governance controls, each with the evidence behind its status.</span>
            </li>
            <li>
              <IconCheckCircle size={18} />
              <span>One clear decision per agent: allow, review, or block.</span>
            </li>
            <li>
              <IconCheckCircle size={18} />
              <span>Scans are read-only and offline. Your code is never executed.</span>
            </li>
          </ul>
        </div>
        <p className="auth-foot">{DISCLAIMER}</p>
      </aside>
      <main className="auth-main" id="main">
        <div className="auth-theme">
          <ThemeToggle />
        </div>
        <div className="auth-card">
          <div className="auth-brand-mobile">
            <Brand compact />
          </div>
          <h1>{title}</h1>
          <p className="lead">{lead}</p>
          {children}
          <p className="auth-foot-mobile">{DISCLAIMER}</p>
        </div>
      </main>
    </div>
  );
}
