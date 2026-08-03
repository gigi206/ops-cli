import React, { type ReactNode } from 'react';
import clsx from 'clsx';
import useIsBrowser from '@docusaurus/useIsBrowser';
import type { Props } from '@theme/ColorModeToggle';

// Replaces the single cycling button with a three-segment control. "Auto" is the
// null choice: nothing is stored, so the page follows the operating system and
// keeps following it when the system flips.
const SEGMENTS = [
  { choice: null, key: 'system', label: 'Auto', title: 'Follow the system setting' },
  { choice: 'light', key: 'light', label: 'Light', title: 'Always light' },
  { choice: 'dark', key: 'dark', label: 'Dark', title: 'Always dark' },
] as const;

function ColorModeToggle({ className, value, onChange }: Props): ReactNode {
  // Until hydration the pressed state is expressed by CSS off the
  // data-theme-choice attribute the theme sets on <html>, so no attribute is
  // emitted server-side that the client would then have to correct.
  const isBrowser = useIsBrowser();

  return (
    <div
      className={clsx('theme-toggle', className)}
      role="group"
      aria-label="Colour mode"
    >
      {SEGMENTS.map(({ choice, key, label, title }) => (
        <button
          key={key}
          type="button"
          className={clsx('clean-btn', 'theme-toggle__option', `theme-toggle__option--${key}`)}
          title={title}
          aria-pressed={isBrowser ? value === choice : undefined}
          disabled={!isBrowser}
          onClick={() => onChange(choice)}
        >
          {label}
        </button>
      ))}
    </div>
  );
}

export default React.memo(ColorModeToggle);
