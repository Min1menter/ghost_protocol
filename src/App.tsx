import { useEffect, useState } from "react";
import { getCurrentWebviewWindow } from "@tauri-apps/api/webviewWindow";
import Dashboard from "./components/Dashboard";
import PetOverlay from "./components/PetOverlay2";
import AlertWindow from "./components/AlertWindow"; // ✅ add this
import "./App.css";

function App() {
  const [windowLabel, setWindowLabel] = useState<string>("");

  useEffect(() => {
    const currentWindow = getCurrentWebviewWindow();
    const label = currentWindow.label;
    console.log("App: Window label is:", label);
    setWindowLabel(label);
  }, []);

  console.log("App: Rendering for window:", windowLabel);

  if (windowLabel === "pet") {
    console.log("App: Loading PetOverlay");
    return <PetOverlay />;
  }

  if (windowLabel === "alert") {
    console.log("App: Loading AlertWindow");
    return <AlertWindow />;
  }

  console.log("App: Loading Dashboard");
  return <Dashboard />;
}

export default App;