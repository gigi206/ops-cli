import React, { useEffect, type ReactNode } from 'react';
import Provider from '@theme-original/Layout/Provider';
import { useColorMode } from '@docusaurus/theme-common';
import type { Props } from '@theme/Layout/Provider';

/**
 * Re-reads the system preference once the page is live.
 *
 * The mode is decided by an inline script, before the first paint, from
 * prefers-color-scheme; the theme only starts listening for changes to that
 * query once React has hydrated. A browser that settles its preference in
 * between answers "light" to the script and "dark" to everything after it: on
 * Linux the desktop portal replies asynchronously, so a cold browser opening
 * its first page routinely lands in that window. Nothing then corrects the
 * mode, and "Auto" stays on the wrong one until the next reload.
 *
 * Reading the query again on mount closes the window. It is the same recovery
 * as pressing "Auto" by hand, which is how the gap surfaces in the first place.
 */
function SystemColorModeSync(): null {
  const { setColorMode } = useColorMode();

  useEffect(() => {
    // The attribute, not the context value: on hydration the context reports
    // "system" for everyone, including a visitor who chose light or dark, and
    // only catches up one render later. The attribute was written by the inline
    // script and already holds the real choice.
    if (document.documentElement.getAttribute('data-theme-choice') !== 'system') return;

    const system = window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
    if (document.documentElement.getAttribute('data-theme') === system) return;

    // Null is the "follow the system" choice: it re-derives the mode and stores
    // nothing, so Auto keeps following the system afterwards.
    setColorMode(null);
  }, [setColorMode]);

  return null;
}

export default function LayoutProvider({ children }: Props): ReactNode {
  return (
    <Provider>
      <SystemColorModeSync />
      {children}
    </Provider>
  );
}
