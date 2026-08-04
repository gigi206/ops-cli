import React, { useCallback, useEffect, useRef, type ReactNode } from 'react';
import { useLocation } from '@docusaurus/router';

// The reading position, as a rule across the top of every page.
//
// It lives in Root rather than in a page because Root is the one component that
// survives a client-side route change: the listener is attached once for the
// life of the tab instead of being torn down and rebuilt on every navigation.
// Only the repaint follows the route, since a new page arrives scrolled to the
// top with a height of its own.
function ScrollProgress(): ReactNode {
  const fill = useRef<HTMLSpanElement>(null);
  const frame = useRef(0);
  const { pathname } = useLocation();

  const paint = useCallback(() => {
    frame.current = 0;
    const el = fill.current;
    if (!el) return;
    const max = document.documentElement.scrollHeight - window.innerHeight;
    const ratio = max > 0 ? Math.min(100, (window.scrollY / max) * 100) : 0;
    el.style.width = `${ratio}%`;
  }, []);

  useEffect(() => {
    const schedule = (): void => {
      if (!frame.current) frame.current = requestAnimationFrame(paint);
    };
    window.addEventListener('scroll', schedule, { passive: true });
    window.addEventListener('resize', schedule, { passive: true });
    return () => {
      window.removeEventListener('scroll', schedule);
      window.removeEventListener('resize', schedule);
      if (frame.current) cancelAnimationFrame(frame.current);
    };
  }, [paint]);

  useEffect(paint, [paint, pathname]);

  return (
    <div className="scroll-progress" aria-hidden="true">
      <span ref={fill} />
    </div>
  );
}

export default function Root({ children }: { children: ReactNode }): ReactNode {
  return (
    <>
      <ScrollProgress />
      {children}
    </>
  );
}
