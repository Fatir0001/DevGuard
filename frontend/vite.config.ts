import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

const localApiProxy = {
  "/api": {
    target: "http://127.0.0.1:8000",
    changeOrigin: true,
  },
};

export default defineConfig({
  plugins: [react()],
  preview: { proxy: localApiProxy },
});
