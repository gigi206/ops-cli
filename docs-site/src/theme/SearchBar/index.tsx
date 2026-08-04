import React, { useEffect, useRef, useState, type ReactNode } from 'react';
import useDocusaurusContext from '@docusaurus/useDocusaurusContext';

// Pagefind indexes the built HTML (package.json "postbuild" runs
// `pagefind --site build`), so no search plugin is needed at build time. This
// component fills the theme's own search slot, which is why the field sits with
// the other navbar controls instead of being appended to the bar by hand.
//
// Only pagefind-ui.js is loaded as a classic script: it is an IIFE that attaches
// window.PagefindUI. The search core, pagefind.js, is an ES module using
// import.meta and cannot run from a <script> tag — the UI imports it itself from
// `bundlePath`. pagefind-ui.css comes along; the widget ships unstyled otherwise.

type PagefindUIConstructor = new (options: Record<string, unknown>) => void;

function loadScript(src: string): Promise<void> {
  const existing = document.querySelector<HTMLScriptElement>(`script[src="${src}"]`);
  if (existing) {
    return existing.dataset.loaded === 'true'
      ? Promise.resolve()
      : new Promise((resolve, reject) => {
          existing.addEventListener('load', () => resolve());
          existing.addEventListener('error', () => reject(new Error(`failed to load ${src}`)));
        });
  }
  return new Promise((resolve, reject) => {
    const el = document.createElement('script');
    el.src = src;
    el.async = true;
    el.onload = () => {
      el.dataset.loaded = 'true';
      resolve();
    };
    el.onerror = () => reject(new Error(`failed to load ${src}`));
    document.head.appendChild(el);
  });
}

function loadStyle(href: string): void {
  if (document.querySelector(`link[href="${href}"]`)) return;
  const el = document.createElement('link');
  el.rel = 'stylesheet';
  el.href = href;
  document.head.appendChild(el);
}

export default function SearchBar(): ReactNode {
  const {
    siteConfig: { baseUrl },
  } = useDocusaurusContext();
  const wrapperRef = useRef<HTMLDivElement>(null);
  const mountRef = useRef<HTMLDivElement>(null);
  const [filled, setFilled] = useState(false);
  const [open, setOpen] = useState(false);
  const [unavailable, setUnavailable] = useState(false);

  useEffect(() => {
    const mount = mountRef.current;
    // A second run (React strict mode) must not stack a second widget.
    if (!mount || mount.childElementCount > 0) return undefined;

    let cancelled = false;
    void (async () => {
      try {
        loadStyle(`${baseUrl}pagefind/pagefind-ui.css`);
        await loadScript(`${baseUrl}pagefind/pagefind-ui.js`);
        if (cancelled) return;
        const PagefindUI = (window as unknown as { PagefindUI: PagefindUIConstructor }).PagefindUI;
        new PagefindUI({
          element: mount,
          // Where the widget finds the index and the search core.
          bundlePath: `${baseUrl}pagefind/`,
          // The index holds site-root paths; result links need the site prefix.
          baseUrl,
          showImages: false,
          showSubResults: true,
          translations: {
            placeholder: 'Search',
            zero_results: 'No results for [SEARCH_TERM]',
          },
        });
        const input = mount.querySelector('input');
        input?.setAttribute('spellcheck', 'false');
        input?.setAttribute('autocomplete', 'off');
        input?.addEventListener('input', () => {
          setFilled(input.value.length > 0);
          setOpen(true);
        });
        // Coming back to a field that still holds a query shows its results again.
        input?.addEventListener('focus', () => setOpen(true));
      } catch (err) {
        // The index only exists after `docusaurus build` plus the pagefind
        // postbuild step, so `docusaurus start` legitimately lands here.
        console.error('[pagefind] mount failed', err);
        if (!cancelled) setUnavailable(true);
      }
    })();

    return () => {
      cancelled = true;
    };
  }, [baseUrl]);

  useEffect(() => {
    function onKeyDown(event: KeyboardEvent) {
      const input = mountRef.current?.querySelector('input');
      if (!input) return;
      // The sliding menu takes the field out of the page for as long as it is
      // open; claiming the shortcut then would swallow it and focus nothing.
      if (input.checkVisibility?.({ visibilityProperty: true }) === false) return;
      if (event.key === 'k' && (event.metaKey || event.ctrlKey)) {
        event.preventDefault();
        input.focus();
      } else if (event.key === 'Escape' && document.activeElement === input) {
        setOpen(false);
        input.blur();
      }
    }

    // The widget keeps its result panel up for as long as the query stands, so
    // dismissing it on an outside click is the theme's job. The query is left
    // alone: focusing the field again brings the same results back.
    function onPointerDown(event: PointerEvent) {
      if (!wrapperRef.current?.contains(event.target as Node)) setOpen(false);
    }

    document.addEventListener('keydown', onKeyDown);
    document.addEventListener('pointerdown', onPointerDown);
    return () => {
      document.removeEventListener('keydown', onKeyDown);
      document.removeEventListener('pointerdown', onPointerDown);
    };
  }, []);

  return (
    // The id sits on the wrapper on purpose: the widget's own stylesheet is
    // injected after the site's and matches at equal specificity, so the theme's
    // rules have to be able to outrank it from an id.
    <div
      id="pagefind-search-mount"
      ref={wrapperRef}
      className={`navbar__search${filled ? ' navbar__search--filled' : ''}${
        open ? '' : ' navbar__search--closed'
      }`}
    >
      <div className="pagefind-mount" ref={mountRef} />
      {unavailable && (
        <form className="pagefind-ui__form">
          <input className="pagefind-ui__search-input" placeholder="Search (build only)" disabled />
        </form>
      )}
      {/* The badge is the design's ⌘K on every platform. Ctrl+K is what actually
          fires outside macOS, so the glyph is decorative: aria-hidden keeps a
          screen reader from announcing a chord that does not exist there. */}
      {!unavailable && (
        <span className="navbar__search-hint" aria-hidden="true">
          ⌘K
        </span>
      )}
    </div>
  );
}
