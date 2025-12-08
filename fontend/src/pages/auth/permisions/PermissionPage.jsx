import React, { useState } from "react";

const permissionsData = [
  { name: "Product" },
  { name: "Orders" },
  { name: "Users" },
  { name: "Reports" },
];

const permissionTypes = ["All", "Create", "Edit", "View", "Delete"];

const PermissionPage = () => {
  const [permissions, setPermissions] = useState({});

  const handleCheckboxChange = (item, type) => {
    setPermissions((prev) => {
      const current = prev[item] || {};

      // If "All" is toggled, apply to all
      if (type === "All") {
        const newValue = !current.All;
        const allPerms = {};
        permissionTypes.forEach((t) => (allPerms[t] = newValue));
        return { ...prev, [item]: allPerms };
      }

      // Toggle specific permission
      const updated = { ...current, [type]: !current[type] };

      // If all individual permissions are checked, set All=true
      const allSelected = permissionTypes
        .filter((t) => t !== "All")
        .every((t) => updated[t]);
      updated.All = allSelected;

      return { ...prev, [item]: updated };
    });
  };

  return (
    <div className="p-4 max-w-6xl mx-auto  dark:bg-neutral-900 dark:text-white ">
      {/* Global Heading */}
      <h1 className="text-2xl font-bold mb-6 text-center">
        Permission Management
      </h1>
      <div className="space-y-6">
        {permissionsData.map((item) => (
          <div
            key={item.name}
            className="bg-white rounded-xl  dark:border-gray-300 shadow-md p-4 sm:p-6  dark:bg-neutral-900 dark:text-white dark:border-1  dark:hover:border-gray-300 dark:hover:shadow-[0_0_10px_2px_rgba(255,255,255,0.7)] transition-all duration-300 hover:scale-102 transform  ease-in-out"
          >
            {/* Component Heading */}
            <h2 className="text-lg font-semibold mb-4">
              {item.name} Permissions
            </h2>

            {/* Checkboxes - Responsive Grid */}
            <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-5 gap-4 ">
              {permissionTypes.map((type) => (
                <label
                  key={type}
                  className="flex items-center gap-2 cursor-pointer"
                >
                  <input
                    type="checkbox"
                    checked={permissions[item.name]?.[type] || false}
                    onChange={() => handleCheckboxChange(item.name, type)}
                    className="w-5 h-5 text-blue-600 border-gray-300 rounded focus:ring-0 accent-blue-500"
                  />
                  <span className="text-sm sm:text-base">{type}</span>
                </label>
              ))}
            </div>
          </div>
        ))}
      </div>
    
    </div>
  );
};

export default PermissionPage;
