import { AppShell } from "@/components/app-shell";
import { SessionProvider } from "@/components/session";

export default function ConsoleLayout({ children }: { children: React.ReactNode }) {
  return (
    <SessionProvider>
      <AppShell>{children}</AppShell>
    </SessionProvider>
  );
}
