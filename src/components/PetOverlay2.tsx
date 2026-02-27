import { useEffect, useRef, useState } from "react";
import { getCurrentWebviewWindow } from "@tauri-apps/api/webviewWindow";

type ThreatAlertPayload = {
  threat_type?: string;
  severity?: string;
  target?: string;
  timestamp?: string;
  message?: string;
};

function PetOverlay() {
  const [isAlarmed, setIsAlarmed] = useState(false);
  const [alertCount, setAlertCount] = useState(0);

  // NEW: store latest alert so we can show it in the popup
  const [latestAlert, setLatestAlert] = useState<ThreatAlertPayload | null>(null);

  // NEW: controls popup visibility
  const [showPopup, setShowPopup] = useState(false);

  const timeoutRef = useRef<number | null>(null);
  const popupTimeoutRef = useRef<number | null>(null);

  useEffect(() => {
    const currentWindow = getCurrentWebviewWindow();
    let cancelled = false;
    let unlisten: null | (() => void) = null;

    const setup = async () => {
      try {
        unlisten = await currentWindow.listen<ThreatAlertPayload>("pet-threat-alert", (event) => {
          console.log("PetOverlay: pet-threat-alert", event.payload);

          setAlertCount((p) => p + 1);
          setIsAlarmed(true);

          // NEW: update popup content + show it
          setLatestAlert(event.payload ?? null);
          setShowPopup(true);

          // Prevent stacking timeouts when alerts arrive quickly
          if (timeoutRef.current) window.clearTimeout(timeoutRef.current);
          timeoutRef.current = window.setTimeout(() => {
            setIsAlarmed(false);
            timeoutRef.current = null;
          }, 3000);

          // NEW: auto-hide popup after a bit (and reset timer on every new alert)
          if (popupTimeoutRef.current) window.clearTimeout(popupTimeoutRef.current);
          popupTimeoutRef.current = window.setTimeout(() => {
            setShowPopup(false);
            popupTimeoutRef.current = null;
          }, 6000);
        });

        if (cancelled && unlisten) {
          unlisten();
          unlisten = null;
        }
      } catch (e) {
        console.error("PetOverlay: Failed to setup listener:", e);
      }
    };

    setup();

    return () => {
      cancelled = true;
      if (timeoutRef.current) window.clearTimeout(timeoutRef.current);
      if (popupTimeoutRef.current) window.clearTimeout(popupTimeoutRef.current);
      if (unlisten) unlisten();
    };
  }, []);

  const appWindow = getCurrentWebviewWindow();

  // Drag the actual Tauri window when user clicks/holds the pet
  const startDrag = async (e: React.MouseEvent | React.PointerEvent) => {
    e.preventDefault();
    e.stopPropagation();

    try {
      await appWindow.startDragging();
    } catch (err) {
      console.error("PetOverlay: startDragging failed:", err);
    }
  };

  const showDebug = import.meta.env.DEV;

  const severity = (latestAlert?.severity ?? "").toUpperCase();
  const threatType = latestAlert?.threat_type ?? "Unknown threat";
  const target = latestAlert?.target ?? "Unknown target";
  const msg = latestAlert?.message ?? "No details provided";
  const time = latestAlert?.timestamp ?? "";

  const severityBadgeBg =
    severity === "CRITICAL" || severity === "HIGH"
      ? "#ef4444"
      : severity === "MEDIUM"
      ? "#f59e0b"
      : "#22c55e";

  return (
    <div className="w-screen h-screen bg-transparent relative overflow-hidden">
      {showDebug && (
        <div
          className="absolute top-2 left-2 text-xs font-bold px-2 py-1 rounded"
          style={{
            backgroundColor: isAlarmed ? "#ef4444" : "#8b5cf6",
            color: "white",
            zIndex: 50,
          }}
        >
          {isAlarmed ? `ALERT! (${alertCount})` : `Safe (${alertCount})`}
        </div>
      )}

      {/* NEW: Popup box */}
      {showPopup && latestAlert && (
        <div
          className="absolute left-1/2 -translate-x-1/2"
          style={{
            top: 8,
            zIndex: 60,
            width: 240,
            borderRadius: 12,
            background: "rgba(17, 24, 39, 0.92)", // dark translucent
            color: "white",
            padding: "10px 12px",
            boxShadow: "0 10px 30px rgba(0,0,0,0.35)",
            backdropFilter: "blur(6px)",
          }}
        >
          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <span
              style={{
                display: "inline-block",
                padding: "2px 8px",
                borderRadius: 999,
                background: severityBadgeBg,
                fontSize: 12,
                fontWeight: 800,
              }}
            >
              {severity || "INFO"}
            </span>
            <div style={{ fontSize: 13, fontWeight: 800, lineHeight: 1.2 }}>
              {threatType}
            </div>
          </div>

          <div style={{ marginTop: 6, fontSize: 12, opacity: 0.95 }}>
            <div>
              <span style={{ opacity: 0.75 }}>Target:</span>{" "}
              <span style={{ fontWeight: 700 }}>{target}</span>
            </div>
            <div style={{ marginTop: 4 }}>
              <span style={{ opacity: 0.75 }}>Details:</span>{" "}
              <span>{msg}</span>
            </div>
            {time ? (
              <div style={{ marginTop: 6, fontSize: 11, opacity: 0.7 }}>
                {time}
              </div>
            ) : null}
          </div>

          {/* optional close button */}
          <button
            onMouseDown={(e) => e.stopPropagation()}
            onClick={() => setShowPopup(false)}
            style={{
              position: "absolute",
              top: 6,
              right: 8,
              width: 22,
              height: 22,
              borderRadius: 999,
              border: "none",
              background: "rgba(255,255,255,0.12)",
              color: "white",
              cursor: "pointer",
              fontWeight: 900,
              lineHeight: "22px",
            }}
            aria-label="Close"
            title="Close"
          >
            ×
          </button>
        </div>
      )}

      {/* Drag handle */}
      <div
        className="absolute inset-0 flex items-center justify-center select-none"
        onMouseDown={startDrag}
        onPointerDown={startDrag}
        style={{ cursor: "move" }}
        aria-label="Drag overlay"
        title="Drag me"
      >
        <svg
          width="150"
          height="150"
          viewBox="0 0 150 150"
          className={`transition-all duration-300 ${
            isAlarmed
              ? "animate-shake filter drop-shadow-[0_0_20px_rgba(239,68,68,0.8)]"
              : ""
          }`}
        >
          {/* Body */}
          <path
            d="M 75 30 
               Q 50 30 40 50 
               Q 35 65 35 80 
               L 35 120 
               L 45 110 
               L 55 120 
               L 65 110 
               L 75 120 
               L 85 110 
               L 95 120 
               L 105 110 
               L 115 120 
               L 115 80 
               Q 115 65 110 50 
               Q 100 30 75 30 Z"
            fill={isAlarmed ? "#ef4444" : "#8b5cf6"}
            stroke={isAlarmed ? "#dc2626" : "#7c3aed"}
            strokeWidth="2"
            className="transition-colors duration-300"
          />

          {/* Eyes */}
          <circle cx="60" cy="65" r="8" fill={isAlarmed ? "#fef3c7" : "#ffffff"} />
          <circle cx="62" cy="65" r="4" fill="#1f2937" />

          <circle cx="90" cy="65" r="8" fill={isAlarmed ? "#fef3c7" : "#ffffff"} />
          <circle cx="92" cy="65" r="4" fill="#1f2937" />

          {/* Mouth */}
          <path
            d={isAlarmed ? "M 60 85 Q 75 75 90 85" : "M 60 85 Q 75 95 90 85"}
            stroke="#1f2937"
            strokeWidth="3"
            fill="none"
            strokeLinecap="round"
            className="transition-all duration-300"
          />

          {/* Alarm extras */}
          {isAlarmed && (
            <>
              <circle cx="75" cy="20" r="5" fill="#ef4444" className="animate-ping" />
              <text
                x="75"
                y="145"
                textAnchor="middle"
                fill="#ef4444"
                fontSize="12"
                fontWeight="bold"
              >
                THREAT!
              </text>
            </>
          )}
        </svg>
      </div>
    </div>
  );
}

export default PetOverlay;