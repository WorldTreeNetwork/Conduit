export type ThemeChoice = 'system' | 'light' | 'dark';
const key = 'conduit:theme';
export function loadTheme(): ThemeChoice {
 try { const value = localStorage.getItem(key); return value === 'light' || value === 'dark' ? value : 'system'; } catch { return 'system'; }
}
export function applyTheme(choice: ThemeChoice) {
 if (choice === 'system') document.documentElement.removeAttribute('data-theme');
 else document.documentElement.setAttribute('data-theme', choice);
}
export function saveTheme(choice: ThemeChoice) {
 try { if (choice === 'system') localStorage.removeItem(key); else localStorage.setItem(key, choice); } catch { /* A theme is a local convenience. */ }
 applyTheme(choice);
}
