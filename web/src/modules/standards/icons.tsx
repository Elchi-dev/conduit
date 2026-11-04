// A small stroke icon set for standards and toolkits (24 px grid, 1.6 px).
import type { SVGProps } from "react";

const paths: Record<string, string> = {
  palette: "M12 3a9 9 0 1 0 0 18c1.1 0 1.6-.8 1.6-1.6 0-.5-.2-.8-.5-1.1-.3-.3-.5-.7-.5-1.1 0-.9.7-1.6 1.6-1.6H16a5 5 0 0 0 5-5c0-4-4-7.6-9-7.6ZM7.5 11.5h.01M10 7.5h.01M15 7.5h.01M17.5 11h.01",
  layout: "M4 4h16v16H4zM4 9h16M9 9v11",
  type: "M5 7V5h14v2M12 5v14M9 19h6",
  pen: "M4 20h4L19 9a2.8 2.8 0 0 0-4-4L4 16v4ZM13.5 6.5l4 4",
  code: "m8 8-4 4 4 4M16 8l4 4-4 4M13.5 5l-3 14",
  git: "M6 3v12M18 9a3 3 0 1 0 0-6 3 3 0 0 0 0 6ZM6 21a3 3 0 1 0 0-6 3 3 0 0 0 0 6ZM18 9a9 9 0 0 1-9 9",
  check: "M9 11.5 11.5 14 16 9M4 5a1 1 0 0 1 1-1h14a1 1 0 0 1 1 1v14a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1z",
  shield: "M12 3 4.5 6v5.5c0 4.5 3.2 8.2 7.5 9.5 4.3-1.3 7.5-5 7.5-9.5V6L12 3ZM9 12l2 2 4-4",
  eye: "M2.5 12S6 5.5 12 5.5 21.5 12 21.5 12 18 18.5 12 18.5 2.5 12 2.5 12ZM12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6Z",
  box: "M12 3 4 7v10l8 4 8-4V7l-8-4ZM4 7l8 4 8-4M12 11v10",
  compass: "M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18ZM15.5 8.5l-2 5-5 2 2-5 5-2Z",
  book: "M4 5.5A1.5 1.5 0 0 1 5.5 4H11v16H5.5A1.5 1.5 0 0 1 4 18.5zM20 5.5A1.5 1.5 0 0 0 18.5 4H13v16h5.5a1.5 1.5 0 0 0 1.5-1.5z",
  sparkle: "M12 3.5 13.8 10.2 20.5 12l-6.7 1.8L12 20.5l-1.8-6.7L3.5 12l6.7-1.8L12 3.5Z",
  ruler: "M3.5 15.5 15.5 3.5l5 5-12 12-5-5ZM7 12l2 2M10 9l1.5 1.5M13 6l2 2",
  flag: "M5 21V4M5 4h11l-2 4 2 4H5",
  heart: "M12 20s-7.5-4.6-7.5-10A4.3 4.3 0 0 1 12 7.4 4.3 4.3 0 0 1 19.5 10C19.5 15.4 12 20 12 20Z",
  terminal: "M4 5h16v14H4zM7.5 9.5l2.5 2.5-2.5 2.5M12 15h4",
  mail: "M3.5 6h17v12h-17zM3.5 6.5 12 13l8.5-6.5",
  star: "m12 3.5 2.6 5.4 5.9.8-4.3 4.1 1 5.8-5.2-2.8-5.2 2.8 1-5.8-4.3-4.1 5.9-.8L12 3.5Z",
  layers: "M12 3.5 3 8l9 4.5L21 8l-9-4.5ZM3 12.5l9 4.5 9-4.5M3 16.5l9 4.5 9-4.5",
  rocket: "M14 4c3-1 6-1 6-1s0 3-1 6l-6 6-5-5 6-6ZM9 11l-4 1-2 3 4 1M13 15l-1 4-3 2-1-4M15 9h.01",
  bolt: "M13 3 5 13.5h6L10 21l8-10.5h-6L13 3Z",
  // interface glyphs
  grip: "M9 6h.01M15 6h.01M9 12h.01M15 12h.01M9 18h.01M15 18h.01",
  plus: "M12 5v14M5 12h14",
  x: "M6 6l12 12M18 6 6 18",
  up: "m6 15 6-6 6 6",
  down: "m6 9 6 6 6-6",
  back: "M15 6l-6 6 6 6",
  history: "M3.5 12a8.5 8.5 0 1 0 2.5-6L3.5 8.5M3.5 4v4.5H8M12 7.5V12l3 2",
  upload: "M12 16V4M7 9l5-5 5 5M4 16v4h16v-4",
  downloadIcon: "M12 4v12M7 11l5 5 5-5M4 16v4h16v-4",
  search: "M11 18a7 7 0 1 0 0-14 7 7 0 0 0 0 14ZM20 20l-4-4",
  dot: "M12 12h.01",
};

export const standardIcons = ["palette", "layout", "type", "pen", "code", "git", "check", "shield", "eye", "box", "compass", "book", "sparkle", "ruler", "flag", "heart", "terminal", "mail", "star", "layers", "rocket", "bolt"];

export function Icon({ name, size = 18, ...rest }: { name?: string; size?: number } & SVGProps<SVGSVGElement>) {
  const d = paths[name ?? ""] ?? paths.ruler;
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.6} strokeLinecap="round" strokeLinejoin="round" aria-hidden="true" focusable="false" {...rest}>
      <path d={d} />
    </svg>
  );
}
