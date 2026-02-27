import { useEffect, useRef, useState } from "react";
import { getCurrentWebviewWindow } from "@tauri-apps/api/webviewWindow";

type ThreatAlertPayload = {
  threat_type?: string;
  severity?: string;
  target?: string;
  timestamp?: string;
  message?: string;
  explanation?: string;
  entropy?: number | null;
  additional_info?: any;
};

const ALERT_EVENT = "threat-alert"; // ✅ must match Rust win.emit()

function AlertWindow() {
  const win = useRef(getCurrentWebviewWindow()).current;

  const [isAlarmed, setIsAlarmed] = useState(false);
  const [alertCount, setAlertCount] = useState(0);

  const [latestAlert, setLatestAlert] = useState<ThreatAlertPayload | null>(null);
  const [showPopup, setShowPopup] = useState(false);

  const alarmTimeoutRef = useRef<number | null>(null);
  const popupTimeoutRef = useRef<number | null>(null);

  useEffect(() => {
    // ✅ Keep it hidden until a threat arrives
    win.hide().catch(() => {});

    let unlisten: null | (() => void) = null;
    let cancelled = false;

    const setup = async () => {
      try {
        unlisten = await win.listen<ThreatAlertPayload>(ALERT_EVENT, async (event) => {
          const payload = event.payload ?? null;

          setLatestAlert(payload);
          setAlertCount((p) => p + 1);
          setIsAlarmed(true);
          setShowPopup(true);

          // ✅ Show + focus the alert window on every alert
          try {
            await win.show();
            await win.setFocus();
          } catch {}

          // ✅ reset alarm animation timer
          if (alarmTimeoutRef.current) window.clearTimeout(alarmTimeoutRef.current);
          alarmTimeoutRef.current = window.setTimeout(() => {
            setIsAlarmed(false);
            alarmTimeoutRef.current = null;
          }, 3000);

          // ✅ reset popup auto-hide timer
          if (popupTimeoutRef.current) window.clearTimeout(popupTimeoutRef.current);
          popupTimeoutRef.current = window.setTimeout(async () => {
            setShowPopup(false);
            popupTimeoutRef.current = null;

            // Optional: hide the whole window after popup disappears
            try {
              await win.hide();
            } catch {}
            setLatestAlert(null);
          }, 10000);
        });

        if (cancelled && unlisten) {
          unlisten();
          unlisten = null;
        }
      } catch (err) {
        console.error("AlertWindow: listen failed:", err);
      }
    };

    setup();

    return () => {
      cancelled = true;
      if (alarmTimeoutRef.current) window.clearTimeout(alarmTimeoutRef.current);
      if (popupTimeoutRef.current) window.clearTimeout(popupTimeoutRef.current);
      if (unlisten) unlisten();
    };
  }, [win]);

  const severity = (latestAlert?.severity ?? "").toUpperCase();
  const threatType = latestAlert?.threat_type ?? "Threat Alert";
  const target = latestAlert?.target ?? "Unknown target";
  const msg = latestAlert?.message ?? latestAlert?.explanation ?? "No details provided";
  const time = latestAlert?.timestamp ?? "";

  const severityBadgeBg =
    severity === "CRITICAL" || severity === "HIGH"
      ? "#ef4444"
      : severity === "MEDIUM"
      ? "#f59e0b"
      : "#22c55e";

  const closeNow = async () => {
    if (alarmTimeoutRef.current) window.clearTimeout(alarmTimeoutRef.current);
    if (popupTimeoutRef.current) window.clearTimeout(popupTimeoutRef.current);
    alarmTimeoutRef.current = null;
    popupTimeoutRef.current = null;

    setShowPopup(false);
    setIsAlarmed(false);
    setLatestAlert(null);

    try {
      await win.hide();
    } catch {}
  };

  const startAction = async () => {
    try {
      await win.emit("threat-user-action", {
        action: "START_ACTION",
        threat_type: latestAlert?.threat_type,
        target: latestAlert?.target,
        timestamp: latestAlert?.timestamp,
      });
    } catch (e) {
      console.error("AlertWindow: failed to emit threat-user-action:", e);
    }
  };

  const showDebug = import.meta.env.DEV;

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

      {/* Popup box (same logic as pet) */}
      {showPopup && latestAlert && (
        <div
          className="absolute left-1/2 -translate-x-1/2"
          style={{
            top: 12,
            zIndex: 60,
            width: 320,
            borderRadius: 14,
            background: "rgba(17, 24, 39, 0.92)",
            color: "white",
            padding: "12px 14px",
            boxShadow: "0 10px 30px rgba(0,0,0,0.35)",
            backdropFilter: "blur(8px)",
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

          <div style={{ marginTop: 8, fontSize: 12, opacity: 0.95 }}>
            <div>
              <span style={{ opacity: 0.75 }}>Target:</span>{" "}
              <span style={{ fontWeight: 700 }}>{target}</span>
            </div>

            <div style={{ marginTop: 6 }}>
              <span style={{ opacity: 0.75 }}>Details:</span>{" "}
              <span>{msg}</span>
            </div>

            {time ? (
              <div style={{ marginTop: 8, fontSize: 11, opacity: 0.7 }}>
                {time}
              </div>
            ) : null}
          </div>

          {/* Buttons */}
          <div style={{ marginTop: 10, display: "flex", gap: 8, justifyContent: "flex-end" }}>
            <button
              onMouseDown={(e) => e.stopPropagation()}
              onClick={startAction}
              style={{
                padding: "6px 10px",
                borderRadius: 10,
                border: "none",
                cursor: "pointer",
                background: "rgba(59,130,246,0.35)",
                color: "white",
                fontWeight: 800,
              }}
            >
              Start Action
            </button>

            <button
              onMouseDown={(e) => e.stopPropagation()}
              onClick={closeNow}
              style={{
                padding: "6px 10px",
                borderRadius: 10,
                border: "none",
                cursor: "pointer",
                background: "rgba(255,255,255,0.14)",
                color: "white",
                fontWeight: 700,
              }}
            >
              Close
            </button>
          </div>

          {/* X close button */}
          <button
            onMouseDown={(e) => e.stopPropagation()}
            onClick={closeNow}
            style={{
              position: "absolute",
              top: 8,
              right: 10,
              width: 24,
              height: 24,
              borderRadius: 999,
              border: "none",
              background: "rgba(255,255,255,0.12)",
              color: "white",
              cursor: "pointer",
              fontWeight: 900,
              lineHeight: "24px",
            }}
            aria-label="Close"
            title="Close"
          >
            ×
          </button>
        </div>
      )}

      {/* Center character (same vibe as pet) */}
      <div className="absolute inset-0 flex items-center justify-center select-none">
        <svg
          width="170"
          height="170"
          viewBox="0 0 150 150"
          className={`transition-all duration-300 ${
            isAlarmed ? "animate-shake filter drop-shadow-[0_0_20px_rgba(239,68,68,0.8)]" : ""
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

export default AlertWindow;