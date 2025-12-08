import React, { useEffect } from "react";
import { useClientsData } from "../../../hooks/useClientsData.js";

const ClientData = () => {
  const { mutate, data, error, isPending } = useClientsData();

  // Auto-fetch data on mount
  useEffect(() => {
    mutate();
  }, [mutate]);

  const client = data?.client_data;

  if (isPending) {
    return (
      <div className="flex justify-center items-center h-64  ">
        <p className="text-blue-600 font-medium animate-pulse">
          Loading client details...
        </p>
      </div>
    );
  }

  if (error) {
    return (
      <div className="text-red-600 bg-red-100 p-4 rounded-lg text-center font-semibold">
        {error.message}
      </div>
    );
  }

  if (!client) {
    return (
      <div className="text-gray-500 text-center font-medium mt-6">
        No client details available.
      </div>
    );
  }

  return (
    <div className=" mt-10 p-6  shadow-xl rounded-xl relative bg-white  border border-gray-200  dark:shadow-md dark:bg-neutral-900 dark:text-white hover:scale-102 transition transform duration-300 ease-in-out  dark:hover:border-gray-300 dark:hover:shadow-[0_0_10px_2px_rgba(255,255,255,0.7)] ">
      {/* Info Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-8 ">
        <div className="flex flex-col ">
          <label className="text-gray-700 font-bold mb-1 dark:text-white">Client ID</label>
          <p className="text-gray-800 dark:text-white ">{client.client_id}</p>
        </div>

        <div className="flex flex-col">
          <label className="text-gray-700 font-bold dark:text-white  mb-1">
            Organization Name
          </label>
          <p className="text-gray-800 dark:text-white">{client.org_name}</p>
        </div>

        <div className="flex flex-col">
          <label className="text-gray-700 font-bold dark:text-white  mb-1">Email</label>
          <p className="text-gray-800 dark:text-white">{client.org_email}</p>
        </div>
        <div className="flex flex-col">
          <label className="text-gray-700 font-bold dark:text-white  mb-1">Created At</label>
          <p className="text-gray-800 dark:text-white">
            {new Date(client.created_at).toLocaleDateString()}
          </p>
        </div>
      </div>
    </div>
  );
};

export default ClientData;
