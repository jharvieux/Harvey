import { ImageResponse } from "next/og";

export const size = { width: 1200, height: 630 };
export const contentType = "image/png";
export const alt = "Harvey — Codebase QA for AI-generated apps";

export default function OpengraphImage() {
  return new ImageResponse(
    (
      <div
        style={{
          width: "100%",
          height: "100%",
          display: "flex",
          flexDirection: "column",
          justifyContent: "space-between",
          background: "#0B0E13",
          padding: "72px 80px",
          fontFamily: "sans-serif",
        }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: "18px" }}>
          <div style={{ width: "26px", height: "26px", borderRadius: "6px", background: "#F2A900" }} />
          <div style={{ display: "flex", fontSize: "34px", fontWeight: 700, color: "#E7ECF2" }}>
            harvey
            <span style={{ color: "#656F7C", fontWeight: 500 }}>-qa</span>
          </div>
        </div>

        <div style={{ display: "flex", flexDirection: "column" }}>
          <div style={{ display: "flex", fontSize: "24px", color: "#F2A900", fontWeight: 600, marginBottom: "22px", letterSpacing: "0.04em" }}>
            CODEBASE QA FOR AI-GENERATED APPS
          </div>
          <div style={{ display: "flex", fontSize: "68px", fontWeight: 800, color: "#E7ECF2", lineHeight: 1.05, letterSpacing: "-0.03em" }}>
            The QA leader your codebase never had.
          </div>
          <div style={{ display: "flex", fontSize: "30px", color: "#99A3B0", marginTop: "26px", lineHeight: 1.35, maxWidth: "980px" }}>
            One ten-module audit across security, tests, performance, data, and maintainability — one readiness verdict.
          </div>
        </div>

        <div style={{ display: "flex", alignItems: "center", gap: "16px" }}>
          {["Free scan · $0", "Connected · from $500", "Full audit · from $1,000"].map((t) => (
            <div
              key={t}
              style={{
                display: "flex",
                fontSize: "24px",
                color: "#E7ECF2",
                background: "#141922",
                border: "1px solid #222A35",
                borderRadius: "10px",
                padding: "12px 20px",
              }}
            >
              {t}
            </div>
          ))}
        </div>
      </div>
    ),
    { ...size },
  );
}
