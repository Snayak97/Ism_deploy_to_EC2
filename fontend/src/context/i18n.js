// src/i18n.js
import i18n from "i18next";
import { initReactI18next } from "react-i18next";
import LanguageDetector from "i18next-browser-languagedetector";
import HttpBackend from "i18next-http-backend";

i18n
  .use(HttpBackend) // Load translations via HTTP (dynamic)
  .use(LanguageDetector) // Detect language from browser/localStorage
  .use(initReactI18next)
  .init({
    fallbackLng: "en",
    debug: true, // Turn off in production

    backend: {
      // Translation files path
      loadPath: "/locales/{{lng}}/translation.json"
    },

    interpolation: {
      escapeValue: false // React already escapes
    }
  });

export default i18n;
