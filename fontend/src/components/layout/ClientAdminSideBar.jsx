import React, { useState, useEffect } from "react";
import accurest_logo from "../../assets/accurest_logo.svg";
import { Link, NavLink } from "react-router-dom";
import { FaDatabase } from "react-icons/fa6";

import {
  FaChevronLeft,
  FaChevronRight,
  FaChevronUp,
  FaChevronDown,
} from "react-icons/fa";

import useAuth from "../../hooks/useAuth";
import { sidebarConfig } from "../../constants/sidebarconstant/SidebarConfig";

const ClientAdminSideBar = () => {
  const { auth } = useAuth();

  const formatRoleName = (roleName) => {
  if (!roleName) return "NormalUser"; // fallback if no role is provided
  return roleName
    .split("_")                       // split "client_admin" into ["client", "admin"]
    .map(word => word.charAt(0).toUpperCase() + word.slice(1)) // capitalize each word
    .join("");                        // join into "ClientAdmin"
};

// Usage
const role_name = formatRoleName(auth?.user?.role_name); 
  const role = auth?.user?.role_name || "normal_user"; // fallback role

  const navLinks = sidebarConfig[role] || [];

  const [collapsed, setCollapsed] = useState(false);
  const [masterTableOpen, setMasterTableOpen] = useState(false);

  useEffect(() => {
    const handleResize = () => setCollapsed(window.innerWidth < 640);
    handleResize();
    window.addEventListener("resize", handleResize);
    return () => window.removeEventListener("resize", handleResize);
  }, []);

  return (
    <div
      className={`relative bg-white flex flex-col h-screen text-gray-900 shadow-md border-r border-gray-300 transition-width duration-300  dark:bg-neutral-900 dark:text-white ${
        collapsed ? "w-16" : "w-64"
      }`}
    >
      {/* Logo + User */}
      <div className="relative flex flex-col items-center pt-4 pb-2 ">
        <Link to="/clientadmin/dashboard">
          <img
            src={accurest_logo}
            alt="Accurest Logo"
            className="h-14 w-auto mb-0 dark:bg-white dark:rounded-sm transform transition-all duration-300  hover:rotate-[360deg] "
          />
        </Link>
        {!collapsed && (
          <h1 className="text-purple-700 font-bold text-md  text-center mt-1 dark:text-white">
            {role_name || role}
          </h1>
        )}
        <hr className="w-full mt-2 border-gray-300" />
        <button
          onClick={() => setCollapsed((prev) => !prev)}
          className="absolute top-1/2 -right-4 transform -translate-y-1/2 flex items-center justify-center w-8 h-8 rounded-full bg-purple-100 hover:bg-purple-200 text-purple-700 transition duration-200 shadow"
        >
          {collapsed ? (
            <FaChevronRight size={16} />
          ) : (
            <FaChevronLeft size={16} />
          )}
        </button>
      </div>

      {/* Navigation */}
      <nav className="flex-1 flex flex-col p-2 overflow-y-auto">
        {navLinks.map((nav) => (
          <NavLink
            to={nav.link}
            key={nav.text}
            className={({ isActive }) =>
              `flex items-center gap-3 rounded-md px-3 py-2 mb-1 transition-colors duration-200 cursor-pointer  dark:text-white ${
                isActive
                  ? "bg-blue-700 text-white"
                  : "hover:bg-gray-100 text-gray-700 dark:hover:text-gray-800"
              }`
            }
            end
            title={collapsed ? nav.text : undefined}
          >
            <div className="text-lg">{nav.icon}</div>
            {!collapsed && (
              <span className="text-lg capitalize">{nav.text}</span>
            )}
          </NavLink>
        ))}

        {/* Mastertable Section (only superAdmin) */}
        {role === "super_admin" && (
          <div className="mt-2">
            <button
              onClick={() => setMasterTableOpen((prev) => !prev)}
              className="flex items-center justify-between w-full rounded-md px-3 py-2 mb-1 hover:bg-gray-100 text-gray-700 cursor-pointer transition-colors duration-200 dark:text-white dark:hover:text-gray-800"
              title={collapsed ? "Mastertable Data" : undefined}
            >
              <div className="flex items-center gap-3">
                <FaDatabase className="text-lg" />
                {!collapsed && (
                  <span className="text-lg capitalize font-medium">
                    Mastertable Data
                  </span>
                )}
              </div>
              {!collapsed && (
                <span>
                  {masterTableOpen ? <FaChevronUp /> : <FaChevronDown />}
                </span>
              )}
            </button>

            {!collapsed && masterTableOpen && (
              <div className="ml-8 flex flex-col gap-1">
                <NavLink
                  to="/masterdata/marketplaces"
                  className={({ isActive }) =>
                    isActive
                      ? "bg-blue-600 text-white px-3 py-2 rounded-md"
                      : "hover:bg-gray-100 px-3 py-2 rounded-md dark:hover:text-gray-800"
                  }
                >
                  Marketplace Data
                </NavLink>
                <NavLink
                  to="/masterdata/shipping-locations"
                  className={({ isActive }) =>
                    isActive
                      ? "bg-blue-600 text-white px-3 py-2 rounded-md"
                      : "hover:bg-gray-100 px-3 py-2 rounded-md dark:hover:text-gray-800"
                  }
                >
                  Shipping Location Data
                </NavLink>
                <NavLink
                  to="/masterdata/selling-platforms"
                  className={({ isActive }) =>
                    isActive
                      ? "bg-blue-600 text-white px-3 py-2 rounded-md"
                      : "hover:bg-gray-100 px-3 py-2 rounded-md dark:hover:text-gray-800"
                  }
                >
                  Selling Platform Data
                </NavLink>
                <NavLink
                  to="/masterdata/platforms-master"
                  className={({ isActive }) =>
                    isActive
                      ? "bg-blue-600 text-white px-3 py-2 rounded-md"
                      : "hover:bg-gray-100 px-3 py-2 rounded-md dark:hover:text-gray-800"
                  }
                >
                  Platforms Master Data
                </NavLink>
              </div>
            )}
          </div>
        )}
      </nav>

      {/* Footer */}
      <div className="p-3 text-center text-sm text-gray-500 border-t border-gray-200  dark:text-white">
        {!collapsed && <>&copy; {new Date().getFullYear()} Accurest</>}
      </div>
    </div>
  );
};

export default ClientAdminSideBar;

// import React, { useState, useEffect } from "react";
// import accurest_logo from "../../assets/accurest_logo.svg";

// import { Link, NavLink } from "react-router-dom";
// import { RxDashboard } from "react-icons/rx";
// import { BsArrowDownUp } from "react-icons/bs";
// import { MdOutlineProductionQuantityLimits } from "react-icons/md";
// import { FaDatabase } from "react-icons/fa6";
// import {
//   FaChevronLeft,
//   FaChevronRight,
//   FaChevronUp,
//   FaChevronDown,
// } from "react-icons/fa";
// import { FaUserLarge } from "react-icons/fa6";

// import useAuth from "../../hooks/useAuth";

// // import { useTranslation } from "react-i18next";

// const ClientAdminSideBar = () => {
//   const [masterTableOpen, setMasterTableOpen] = useState(false);
//   const [collapsed, setCollapsed] = useState(false);
//   const { auth } = useAuth();

//   useEffect(() => {
//     const handleResize = () => {
//       if (window.innerWidth < 640) {
//         setCollapsed(true);
//       } else {
//         setCollapsed(false);
//       }
//     };
//     handleResize(); // initial check
//     window.addEventListener("resize", handleResize);
//     return () => window.removeEventListener("resize", handleResize);
//   }, []);

//   const navLink = [
//     {
//       icon: <RxDashboard />,
//       text: "DashBoard",
//       link: "/clientadmin/dashboard",
//     },
//     {
//       icon: <FaDatabase />,
//       text: "UploadMasters",
//       link: "/clientadmin/uploadmasters",
//     },
//     {
//       icon: <MdOutlineProductionQuantityLimits />,
//       text: "Products",
//       link: "/clientadmin/products",
//     },
//     {
//       icon: <BsArrowDownUp />,
//       text: "Transactions",
//       link: "/clientadmin/transaction",
//     },
//     { icon: <FaUserLarge />, text: "Users", link: "/clientadmin/users" },
//   ];

//   return (
//     <div
//       className={`relative bg-white flex flex-col h-screen text-gray-900 shadow-md border-r border-gray-300 transition-width duration-300 ${
//         collapsed ? "w-16" : "w-64"
//       }`}
//     >
//       <div className="relative flex flex-col items-center pt-4 pb-2">
//         <Link to="/clientadmin/dashboard">
//           <img
//             src={accurest_logo}
//             alt="Accurest Logo"
//             className="h-14 w-auto mb-0"
//           />
//         </Link>
//         {!collapsed && (
//           <h1 className="text-purple-700 font-bold text-md underline text-center mt-1">
//             {auth?.user?.user_name}
//           </h1>
//         )}
//         <hr className="w-full mt-2 border-gray-300" />

//         {/* Collapse / Expand Button */}
//         <button
//           onClick={() => setCollapsed((prev) => !prev)}
//           aria-label={collapsed ? "Expand sidebar" : "Collapse sidebar"}
//           className="absolute top-1/2 -right-4 transform -translate-y-1/2 flex items-center justify-center w-8 h-8 rounded-full bg-purple-100 hover:bg-purple-200 text-purple-700 transition duration-200 shadow"
//         >
//           {collapsed ? (
//             <FaChevronRight size={16} />
//           ) : (
//             <FaChevronLeft size={16} />
//           )}
//         </button>
//       </div>

//       {/* Navigation */}
//       <nav className="flex-1 flex flex-col p-2 overflow-y-auto">
//         {navLink.map((nav) => (
//           <NavLink
//             to={nav.link}
//             key={nav.text}
//             className={({ isActive }) =>
//               `flex items-center gap-3 rounded-md px-3 py-2 mb-1 transition-colors duration-200 cursor-pointer ${
//                 isActive
//                   ? "bg-blue-700 text-white"
//                   : "hover:bg-gray-100 text-gray-700"
//               }`
//             }
//             end
//             title={collapsed ? nav.text : undefined}
//           >
//             <div className="text-lg">{nav.icon}</div>
//             {!collapsed && (
//               <span className="text-lg capitalize">{nav.text}</span>
//             )}
//           </NavLink>
//         ))}

//         {/* Mastertable Section */}
//         <div className="mt-2">
//           <button
//             type="button"
//             onClick={() => setMasterTableOpen((prev) => !prev)}
//             className="flex items-center justify-between w-full rounded-md px-3 py-2 mb-1 hover:bg-gray-100 text-gray-700 cursor-pointer transition-colors duration-200"
//             title={collapsed ? "Mastertable Data" : undefined}
//           >
//             <div className="flex items-center gap-3">
//               <FaDatabase className="text-lg" />
//               {!collapsed && (
//                 <span className="text-lg capitalize font-medium">
//                   Mastertable Data
//                 </span>
//               )}
//             </div>
//             {!collapsed && (
//               <span>
//                 {masterTableOpen ? (
//                   <FaChevronUp className="text-lg" />
//                 ) : (
//                   <FaChevronDown className="text-lg" />
//                 )}
//               </span>
//             )}
//           </button>

//           {!collapsed && masterTableOpen && (
//             <div className="ml-8 flex flex-col gap-1">
//               <NavLink
//                 to="/masterdata/marketplaces"
//                 className={({ isActive }) =>
//                   `px-3 py-2 rounded-md cursor-pointer transition-colors duration-200 ${
//                     isActive
//                       ? "bg-blue-600 text-white"
//                       : "hover:bg-gray-100 text-gray-700"
//                   }`
//                 }
//                 end
//               >
//                 Marketplace Data
//               </NavLink>
//               <NavLink
//                 to="/masterdata/shipping-locations"
//                 className={({ isActive }) =>
//                   `px-3 py-2 rounded-md cursor-pointer transition-colors duration-200 ${
//                     isActive
//                       ? "bg-blue-600 text-white"
//                       : "hover:bg-gray-100 text-gray-700"
//                   }`
//                 }
//                 end
//               >
//                 Shipping Location Data
//               </NavLink>
//               <NavLink
//                 to="/masterdata/selling-platforms"
//                 className={({ isActive }) =>
//                   `px-3 py-2 rounded-md cursor-pointer transition-colors duration-200 ${
//                     isActive
//                       ? "bg-blue-600 text-white"
//                       : "hover:bg-gray-100 text-gray-700"
//                   }`
//                 }
//                 end
//               >
//                 Selling Platform Data
//               </NavLink>
//               <NavLink
//                 to="/masterdata/platforms-master"
//                 className={({ isActive }) =>
//                   `px-3 py-2 rounded-md cursor-pointer transition-colors duration-200 ${
//                     isActive
//                       ? "bg-blue-600 text-white"
//                       : "hover:bg-gray-100 text-gray-700"
//                   }`
//                 }
//                 end
//               >
//                 Platforms Master Data
//               </NavLink>
//             </div>
//           )}
//         </div>

//       </nav>

//       {/* Footer */}
//       <div className="p-3 text-center text-sm text-gray-500 border-t border-gray-200">
//         {!collapsed && <>&copy; {new Date().getFullYear()} Accurest</>}
//       </div>
//     </div>
//   );
// };

// export default ClientAdminSideBar;
