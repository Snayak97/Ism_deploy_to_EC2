import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import "./index.css";
import App from "./App.jsx";
import { BrowserRouter } from "react-router";
import AuthProvider from "./context/Auth.jsx";
import { FullscreenProvider } from "./context/FullscreenContext.jsx";
import "./context/i18n.js";

createRoot(document.getElementById("root")).render(
  <StrictMode>
    <BrowserRouter>
      <FullscreenProvider>
        <AuthProvider>
          <App />
        </AuthProvider>
      </FullscreenProvider>
    </BrowserRouter>
  </StrictMode>
);
