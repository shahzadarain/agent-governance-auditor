// SPDX-License-Identifier: Apache-2.0
//
// Theme preference. This is the only value the dashboard keeps in
// localStorage. Without a stored choice the page follows the system setting.

export type ThemeChoice = "light" | "dark" | "system";

const KEY = "agentgov-theme";

export function storedTheme(): ThemeChoice {
  try {
    const v = window.localStorage.getItem(KEY);
    return v === "light" || v === "dark" ? v : "system";
  } catch {
    return "system";
  }
}

export function systemPrefersDark(): boolean {
  return typeof window.matchMedia === "function" && window.matchMedia("(prefers-color-scheme: dark)").matches;
}

export function effectiveTheme(choice: ThemeChoice): "light" | "dark" {
  if (choice === "system") return systemPrefersDark() ? "dark" : "light";
  return choice;
}

export function applyTheme(choice: ThemeChoice): void {
  const root = document.documentElement;
  if (choice === "system") root.removeAttribute("data-theme");
  else root.setAttribute("data-theme", choice);
}

export function saveTheme(choice: ThemeChoice): void {
  try {
    if (choice === "system") window.localStorage.removeItem(KEY);
    else window.localStorage.setItem(KEY, choice);
  } catch {
    // Storage can be unavailable (private mode). The choice then lasts for this page only.
  }
  applyTheme(choice);
}
