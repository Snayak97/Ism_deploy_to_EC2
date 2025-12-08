
import React, { useState, useEffect } from "react";
import { useMutation } from "@tanstack/react-query";
import { updateUserProfile } from "../../services/AuthServices";
import useAuth from "../../hooks/useAuth";

const UserEditProfiles = ({ user, setUserData }) => {

  const { setAuth } = useAuth()

  const [isEditing, setIsEditing] = useState(false);
  const [formData, setFormData] = useState({
    user_name: "",
    email: "",
    mobile_number: "",
  });

  // Initialize formData when user changes
  useEffect(() => {
    if (user) {
      setFormData({
        user_name: user.user_name || "",
        email: user.email || "",
        mobile_number: user.mobile_number || "",
      });
    }
  }, [user]);

  // React Query mutation
  const mutation = useMutation({
    mutationFn: ({ userId, formData }) => updateUserProfile(userId, formData),
    onSuccess: (res) => {
      const { user: updatedUser, message } = res; // match your service
      setUserData(updatedUser); // update parent
      setAuth(prev => ({ ...prev, user: updatedUser }));
      alert(message || "User updated successfully!");
      setIsEditing(false);
    },
    onError: (error) => {
      alert(error.message || "Error updating user.");
    },
  });

  const handleEditToggle = () => setIsEditing(!isEditing);

  const handleChange = (e) =>
    setFormData((prev) => ({ ...prev, [e.target.name]: e.target.value }));

  const handleSave = () => {
    mutation.mutate({ userId: user.user_id, formData });
  };

  if (!user) return <p>Loading...</p>;

  return (
    <div className="mx-auto mt-10 p-6 bg-white shadow-lg rounded-xl relative border border-gray-200  dark:shadow-md dark:bg-neutral-900 dark:text-white hover:scale-101 transition transform duration-300 ease-in-out  dark:hover:border-gray-300 dark:hover:shadow-[0_0_10px_2px_rgba(255,255,255,0.7)]">
      {/* Edit / Cancel + Save buttons */}
      <div className="absolute top-4 right-4 flex gap-2 ">
        {!isEditing ? (
          <button
            onClick={handleEditToggle}
            className="bg-blue-500 hover:bg-blue-600 text-white px-4 py-1 rounded transition"
          >
            Edit
          </button>
        ) : (
          <>
            <button
              onClick={handleEditToggle}
              className="bg-gray-400 hover:bg-gray-500 text-white px-4 py-1 rounded transition disabled:opacity-50"
              disabled={mutation.isLoading}
            >
              Cancel
            </button>
            <button
              onClick={handleSave}
              className="bg-green-500 hover:bg-green-600 text-white px-4 py-1 rounded transition disabled:opacity-50"
              disabled={mutation.isLoading}
            >
              {mutation.isLoading ? "Saving..." : "Save"}
            </button>
          </>
        )}
      </div>

      {/* First Row: Editable fields */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6 ">
        {/* Name */}
        <div className="flex flex-col">
          <label className="text-gray-700 font-medium mb-1 dark:text-white">Name</label>
          {isEditing ? (
            <input
              type="text"
              name="user_name"
              value={formData.user_name}
              onChange={handleChange}
              placeholder="Enter name"
              className="border rounded-md w-58 px-4 py-2 focus:outline-none focus:ring-2 focus:ring-blue-400 transition"
            />
          ) : (
            <p className="text-gray-800 dark:text-gray-200">{user.user_name}</p>
          )}
        </div>

        {/* Email */}
        <div className="flex flex-col">
          <label className="text-gray-700 font-medium mb-1 dark:text-white">Email</label>
          {isEditing ? (
            <input
              type="email"
              name="email"
              value={formData.email}
              onChange={handleChange}
              placeholder="Enter email"
              disabled={!!isEditing}
              // className="border rounded-md px-4 py-2 focus:outline-none focus:ring-2 focus:ring-blue-400 transition"
            />
          ) : (
            <p className="text-gray-800 dark:text-gray-200">{user.email}</p>
          )}
        </div>

        {/* Mobile */}
        <div className="flex flex-col">
          <label className="text-gray-700 font-medium mb-1 dark:text-white">Mobile</label>
          {isEditing ? (
            <input
              type="text"
              name="mobile_number"
              value={formData.mobile_number}
              onChange={handleChange}
              placeholder="Enter mobile"
              className="border rounded-md px-4 w-58 py-2 focus:outline-none focus:ring-2 focus:ring-blue-400 transition"
            />
          ) : (
            <p className="text-gray-800 dark:text-gray-200">{user.mobile_number || "N/A"}</p>
          )}
        </div>
      </div>

      {/* Second Row: Non-editable fields */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mt-6 ">
        <div className="flex flex-col">
          <label className="text-gray-700 font-medium mb-1 dark:text-white">Role Name</label>
          <p className="text-gray-800 dark:text-gray-200">{user.role_name || "N/A"}</p>
        </div>
        <div className="flex flex-col">
          <label className="text-gray-700 font-medium mb-1 dark:text-white">Activate</label>
          <p className="text-gray-800 dark:text-gray-200">{user.is_active ? "Yes" : "No"}</p>
        </div>
        <div className="flex flex-col">
          <label className="text-gray-700 font-medium mb-1 dark:text-white">Verified</label>
          <p className="text-gray-800 dark:text-gray-200">{user.is_verified ? "Yes" : "No"}</p>
        </div>
      </div>
    </div>
  );
};

export default UserEditProfiles;
