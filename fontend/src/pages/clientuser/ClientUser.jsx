import React, { useEffect, useState } from "react";
import ClientData from "./Clientdta/ClientData";
import ClientUserTable from "./ClientUserTable/ClientUserTable";
import AddClientUser from "./addclientuser/AddClientUser";


const ClientUser = () => {
  const [openForm, setOpenForm] = useState(false);
  const [editData, setEditData] = useState(null);
  const [refreshKey, setRefreshKey] = useState(0);

  const handleAddClick = () => {
    setEditData(null);
    setOpenForm(true);
  };

  const handleEditClick = (user) => {
    setEditData(user);
    setOpenForm(true);
  };

  const handleSuccess = () => {
    setRefreshKey((prev) => prev + 1);
  };
 
    
  return (
    <div className="p-6 w-[95%] dark:shadow-white drak:shadow-md dark:bg-neutral-900 dark:text-white">
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center mb-6 gap-3">
        <h1 className="text-2xl font-bold text-gray-800 dark:text-white">Client Users</h1>
        <button className="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-lg shadow-md transition"
        onClick={handleAddClick}>
          Add Client User
        </button>
      </div>
      <div>
        <ClientData/>
      </div>
      <ClientUserTable
      key={refreshKey}
        onEdit={handleEditClick}
      />
      <AddClientUser
       open={openForm}
        onClose={() => setOpenForm(false)}
        onSuccess={handleSuccess}
        editData={editData}
      />
    </div>
  );
};

export default ClientUser;
