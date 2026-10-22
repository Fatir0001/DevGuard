import { describe, expect, it } from "vitest";
import type { UserConfig } from "vite";
import viteConfig from "../vite.config";

describe("local Vite API routing", () => {
  it("proxies the production preview's relative /api base to local FastAPI", () => {
    const config = viteConfig as UserConfig;

    expect(config.preview?.proxy).toMatchObject({
      "/api": { target: "http://127.0.0.1:8000", changeOrigin: true },
    });
  });
});
