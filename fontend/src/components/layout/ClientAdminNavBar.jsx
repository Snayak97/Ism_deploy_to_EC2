import React, { useContext } from "react";
import { FullscreenContext } from "../../context/FullscreenContext";
import { Link, NavLink } from "react-router-dom";
import {
  FiSearch,
  FiMoon,
  FiMaximize2,
  FiBell,
  FiSun,
  FiMinimize2,
  FiMessageSquare,
  FiList,
} from "react-icons/fi";
import { useTranslation } from "react-i18next";
import LanguageSwitcher from "../Lang/LanguageSwitcher";
import UserMenu from "../ui/Usermenu";
import useAuth from "../../hooks/useAuth";

const ClientAdminNavBar = ({ darkMode, togleDarkMode }) => {
  const { isFullscreen, toggleFullscreen } = useContext(FullscreenContext);
  const { t } = useTranslation();
  const { auth } = useAuth();

  return (
    <div className="bg-white shadow-md h-auto px-4 md:px-6 py-2 flex flex-wrap md:flex-nowrap items-center justify-between gap-2 w-full dark:shadow-white  dark:bg-neutral-900 dark:text-white">
      {/* Left Section: Search Input */}
      <div className="flex items-center border border-gray-300 rounded-md px-2 py-1 w-full sm:max-w-[200px] md:max-w-xs  ">
        <input
          type="text"
          placeholder="Search..."
          className="bg-transparent dark:placeholder-white outline-none text-sm flex-grow"
        />
        <FiSearch className="text-gray-500 dark:text-white"  />
      </div>

      {/* Right Section: Icons & Controls */}
      <div className="flex flex-wrap sm:flex-nowrap items-center justify-end gap-2 sm:gap-4 w-full sm:w-auto ">
        {/* Welcome + Language Switcher */}
        <div className="flex items-center gap-2 sm:gap-3  ">
          <span className="text-sm font-medium hidden sm:inline">
            {t("welcome")}
          </span>
          <LanguageSwitcher  />
        </div>

        {/* Theme Toggle */}
        <button
          onClick={togleDarkMode}
          className="text-xl text-gray-600 hover:text-black  cursor-pointer"
        >
          {darkMode ? <FiSun className="text-gray-700 dark:text-white dark:hover:text-yellow-200" /> : <FiMoon />}
        </button>

        {/* Fullscreen Toggle */}
        <button
          onClick={toggleFullscreen}
          className="text-xl text-gray-600 hover:text-black transition cursor-pointer"
          aria-label={isFullscreen ? "Exit fullscreen" : "Enter fullscreen"}
        >
          {isFullscreen ? <FiMinimize2 className="dark:text-white dark:hover:text-yellow-200" /> : <FiMaximize2 className="dark:text-white dark:hover:text-yellow-200" />}
        </button>

        {/* Notification Icon */}
        <div className="relative cursor-pointer">
          <FiBell className="text-xl text-gray-600 dark:text-white dark:hover:text-yellow-200" />
          <span className="absolute -top-1 -right-1 bg-red-500 text-white text-xs w-4 h-4 flex items-center justify-center rounded-full">
            1
          </span>
        </div>

        {/* Message Icon */}
        <div className="relative cursor-pointer">
          <FiMessageSquare className="text-xl text-gray-600 dark:text-white dark:hover:text-yellow-200 " />
          <span className="absolute -top-1 -right-1 bg-red-500 text-white text-xs w-4 h-4 flex items-center justify-center rounded-full">
            2
          </span>
        </div>

        {/* Sidebar Toggle (FiList) */}
        {/* <FiList className="text-xl text-gray-600 dark:text-white dark:hover:text-yellow-200 " /> */}

        {/* User Menu */}
        
          <UserMenu user={auth?.user} />
        
      </div>
    </div>
  );
};

export default ClientAdminNavBar;
