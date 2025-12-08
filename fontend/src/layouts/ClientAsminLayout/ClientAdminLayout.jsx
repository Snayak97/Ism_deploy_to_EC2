import React, { useState, useEffect } from "react";
import { Outlet } from "react-router-dom";
import ClientAdminSideBar from "../../components/layout/ClientAdminSideBar";
import ClientAdminNavBar from "../../components/layout/ClientAdminNavBar";

// import { useTranslation } from "react-i18next";

const ClientAdminLayout = () => {
  const [darkMode, setDarkMode] = useState(false);

  useEffect(() => {
    if (darkMode) {
      document.documentElement.classList.add("dark");
    } else {
      document.documentElement.classList.remove("dark");
    }
  }, [darkMode]);
  const togleDarkMode = () => {
    setDarkMode((prevMode) => !prevMode);
  };
  return (
    // <div className='flex w-screen h-screen bg-neutral-100 overflow-hidden'>
    //   <div><SideBar/></div>
    //     <div><NavBar/></div>

    // </div>
    <div className="flex w-screen h-screen bg-neutral-100 overflow-hidden  dark:bg-neutral-950 dark:text-white dark:from-gray-950 dark:via-gray-900 dark:to-gray-950">
      <ClientAdminSideBar />
      <div className="flex flex-col flex-1">
        <ClientAdminNavBar darkMode={darkMode} togleDarkMode={togleDarkMode} />
        <div className="flex-1 overflow-auto p-4">
          <Outlet />
        </div>
      </div>
    </div>
  );
};

export default ClientAdminLayout;
