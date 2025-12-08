import React from "react";
import { useTranslation } from "react-i18next";
import { FaGlobe } from "react-icons/fa";

const LanguageSwitcher = () => {
  const { i18n } = useTranslation();

  const changeLanguage = (lng) => {
    i18n.changeLanguage(lng);
  };

  return (
    <div className="flex items-center gap-2 text-sm ">
      <FaGlobe className="text-xl text-gray-600  dark:text-white dark:hover:text-yellow-200" />
      <select
        onChange={(e) => changeLanguage(e.target.value)}
        value={i18n.language}
        className="px-2 py-1 rounded bg-gray-200 text-gray-800"
      >
        <option value="en">English</option>
        <option value="hi">हिंदी</option>
      </select>
    </div>
  );
};

export default LanguageSwitcher;
