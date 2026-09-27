import type { Metadata } from "next";
import { connection } from "next/server";
import "./globals.css";

export const metadata: Metadata = {
  title: "SAMIIR + FATMA Secure AI Platform",
  description: "Customer service (SAMIIR) and defensive SOC (FATMA) console",
  robots: { index: false, follow: false },
};

export default async function RootLayout({ children }: { children: React.ReactNode }) {
  // Nonce-based CSP requires per-request (dynamic) rendering so Next.js can stamp the
  // request's nonce on its scripts (see proxy.ts).
  await connection();
  return (
    <html lang="en">
      <body className="min-h-screen antialiased">{children}</body>
    </html>
  );
}
