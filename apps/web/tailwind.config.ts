import type { Config } from "tailwindcss";

const config: Config = {
  content: ["./app/**/*.{ts,tsx}", "./components/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        bg: "#0b0e14",
        panel: "#111722",
        panel2: "#0f1520",
        border: "#232a36",
        fg: "#e6e9ef",
        muted: "#9aa4b2",
        accent: "#4c8dff",
        ok: "#3fb950",
        warn: "#d29922",
        bad: "#f85149",
        crit: "#ff5c8a",
      },
    },
  },
  plugins: [],
};

export default config;
