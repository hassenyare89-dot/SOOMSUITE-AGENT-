import type { NextConfig } from "next";

const ADMIN = process.env.ADMIN_GATEWAY_URL ?? "http://localhost:8001";
const PUBLIC = process.env.PUBLIC_GATEWAY_URL ?? "http://localhost:8000";

const config: NextConfig = {
  poweredByHeader: false,
  reactStrictMode: true,
  output: "standalone",
  // Same-origin BFF: the browser only ever talks to this origin; cookies stay first-party.
  async rewrites() {
    return [
      { source: "/api/admin/:path*", destination: `${ADMIN}/:path*` },
      { source: "/api/public/:path*", destination: `${PUBLIC}/:path*` },
    ];
  },
  async headers() {
    const common = [
      { key: "Strict-Transport-Security", value: "max-age=63072000; includeSubDomains; preload" },
      { key: "X-Content-Type-Options", value: "nosniff" },
      { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },
      { key: "Permissions-Policy", value: "camera=(), microphone=(), geolocation=(), payment=()" },
      { key: "Cross-Origin-Opener-Policy", value: "same-origin" },
    ];
    return [
      { source: "/:path*", headers: common },
      { source: "/((?!widget).*)", headers: [{ key: "X-Frame-Options", value: "DENY" }] },
      { source: "/widget/loader.js", headers: [{ key: "Cache-Control", value: "public, max-age=300" }] },
    ];
  },
};

export default config;
