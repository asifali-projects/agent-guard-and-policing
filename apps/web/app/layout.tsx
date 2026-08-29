import type { Metadata } from "next";

import { Providers } from "@/lib/providers";
import "./globals.css";

export const metadata: Metadata = {
  title: "AgentGuard",
  description: "Security control plane for AI agents",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>
        <Providers>{children}</Providers>
      </body>
    </html>
  );
}
