import type { Metadata } from "next";
import "../styles/globals.css";

export const metadata: Metadata = {
  title: "OWASP Checklist - Application Security Guide",
  description:
    "Complete AppSec Checklist Manager with OWASP Top 10 frameworks",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <head>
        <meta
          httpEquiv="Content-Security-Policy"
          content="default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' data:; connect-src 'self' localhost:3000; frame-ancestors 'none'; base-uri 'self'; form-action 'self';"
        />
      </head>
      <body>{children}</body>
    </html>
  );
}
