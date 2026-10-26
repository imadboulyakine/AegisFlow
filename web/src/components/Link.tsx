import type { AnchorHTMLAttributes, MouseEvent } from "react";
import { isPlainLeftClick, navigate } from "../lib/router";

type LinkProps = Omit<AnchorHTMLAttributes<HTMLAnchorElement>, "href"> & { to: string };

/** Same-origin link that navigates client-side; modified clicks keep browser behaviour. */
export function Link({ to, onClick, children, ...rest }: LinkProps) {
  function handleClick(event: MouseEvent<HTMLAnchorElement>) {
    onClick?.(event);
    if (!isPlainLeftClick(event)) return;
    event.preventDefault();
    navigate(to);
  }

  return (
    <a href={to} onClick={handleClick} {...rest}>
      {children}
    </a>
  );
}
