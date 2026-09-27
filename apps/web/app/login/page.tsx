"use client";

import * as React from "react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Label, Select } from "@/components/ui/input";
import { api, setCsrf } from "@/lib/api";

const DEV_USERS = ["admin", "admin2", "sales", "support", "analyst", "engineer", "engineer2"];

export default function LoginPage() {
  const [user, setUser] = React.useState("engineer");
  const [tenant, setTenant] = React.useState("acme");
  const [error, setError] = React.useState<string | null>(null);
  const showDev = process.env.NEXT_PUBLIC_DEV_LOGIN === "true";

  async function devLogin() {
    setError(null);
    try {
      const r = await api<{ csrf_token: string }>("/auth/dev-login", {
        method: "POST", json: { subject: `dev|${tenant}|${user}` } });
      setCsrf(r.csrf_token);
      window.location.href = "/";
    } catch (e) {
      setError(e instanceof Error ? e.message : "Login failed");
    }
  }

  return (
    <main className="flex min-h-screen items-center justify-center p-6">
      <Card className="w-full max-w-sm">
        <CardHeader>
          <CardTitle>Sign in</CardTitle>
          <CardDescription>Staff console. Single sign-on with MFA or a passkey is required.</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <a href="/api/admin/auth/login" className="block">
            <Button className="w-full">Continue with SSO</Button>
          </a>
          {showDev ? (
            <div className="space-y-2 border-t border-border pt-4">
              <p className="text-xs text-muted">Local development only — seeded demo users.</p>
              <Label htmlFor="tenant">Tenant</Label>
              <Select id="tenant" value={tenant} onChange={(e) => setTenant(e.target.value)}>
                <option value="acme">Acme Secure</option>
                <option value="globex">Globex Ltd</option>
              </Select>
              <Label htmlFor="user">User</Label>
              <Select id="user" value={user} onChange={(e) => setUser(e.target.value)}>
                {DEV_USERS.map((u) => <option key={u} value={u}>{u}</option>)}
              </Select>
              <Button variant="outline" className="w-full" onClick={() => void devLogin()}>
                Dev sign-in
              </Button>
              {error ? <p role="alert" className="text-xs text-critical">{error}</p> : null}
            </div>
          ) : null}
        </CardContent>
      </Card>
    </main>
  );
}
