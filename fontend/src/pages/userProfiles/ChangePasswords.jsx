import React, { useState } from "react";
import { FiLock, FiKey, FiEye, FiEyeOff } from "react-icons/fi";
import { changePassword } from "../../services/AuthServices";

const ChangePasswords = () => {
  // --- States ---
  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [successMessage, setSuccessMessage] = useState("");
  const [errorMessage, setErrorMessage] = useState("");
  const [loading, setLoading] = useState(false);

  // --- Password visibility ---
  const [showCurrent, setShowCurrent] = useState(false);
  const [showNew, setShowNew] = useState(false);
  const [showConfirm, setShowConfirm] = useState(false);

  // --- Handler ---
  const handleChangePassword = async (e) => {
    e.preventDefault(); // allows Enter key to work
    setSuccessMessage("");
    setErrorMessage("");

    if (!currentPassword || !newPassword || !confirmPassword) {
      setErrorMessage("All fields are required.");
      return;
    }
    if (newPassword !== confirmPassword) {
      setErrorMessage("New passwords do not match!");
      return;
    }

    setLoading(true);
    try {
      const response = await changePassword({
        old_password: currentPassword,
        new_password: newPassword,
        confirm_password: confirmPassword,
      });

      setSuccessMessage(response.message || "Password changed successfully!");
      setCurrentPassword("");
      setNewPassword("");
      setConfirmPassword("");
    } catch (err) {
      setErrorMessage(err.message || "Error changing password.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <form onSubmit={handleChangePassword} className="p-6 bg-gradient-to-r from-green-50 to-green-100 shadow-xl rounded-2xl border border-green-200 dark:shadow-md dark:bg-gradient-to-r dark:from-gray-800 dark:to-gray-900 dark:text-white hover:scale-101 transition transform duration-300 ease-in-out  dark:hover:border-gray-300 dark:hover:shadow-[0_0_10px_2px_rgba(255,255,255,0.7)]">
      <h3 className="text-xl font-semibold mb-6 text-green-700 text-center">
        Change Password
      </h3>

      {/* Success / Error Messages */}
      {successMessage && (
        <div role="alert" className="bg-green-200 text-green-700 text-sm break-words whitespace-pre-wrap p-1 rounded-md text-center font-semibold mb-4">
          {successMessage}
        </div>
      )}
      {errorMessage && (
        <div role="alert" className="bg-red-200 text-red-700 text-sm break-words whitespace-pre-wrap p-1 rounded-md text-center font-semibold mb-4">
          {errorMessage}
        </div>
      )}

      {/* Current Password */}
      <div className="flex items-center mb-3 bg-white rounded-lg shadow-sm border border-gray-200 px-3 py-2 relative">
        <FiLock className="text-gray-400 mr-2 text-lg" />
        <input
          type={showCurrent ? "text" : "password"}
          placeholder="Current Password"
          value={currentPassword}
          onChange={(e) => setCurrentPassword(e.target.value)}
          className="w-full bg-transparent outline-none text-gray-700 placeholder-gray-400 pr-8"
        />
        <span className="absolute right-3 cursor-pointer text-gray-500" onClick={() => setShowCurrent(!showCurrent)}>
          {showCurrent ? <FiEyeOff /> : <FiEye />}
        </span>
      </div>

      {/* New Password */}
      <div className="flex items-center mb-3 bg-white rounded-lg shadow-sm border border-gray-200 px-3 py-2 relative">
        <FiKey className="text-gray-400 mr-2 text-lg" />
        <input
          type={showNew ? "text" : "password"}
          placeholder="New Password"
          value={newPassword}
          onChange={(e) => setNewPassword(e.target.value)}
          className="w-full bg-transparent outline-none text-gray-700 placeholder-gray-400 pr-8"
        />
        <span className="absolute right-3 cursor-pointer text-gray-500" onClick={() => setShowNew(!showNew)}>
          {showNew ? <FiEyeOff /> : <FiEye />}
        </span>
      </div>

      {/* Confirm Password */}
      <div className="flex items-center mb-4 bg-white rounded-lg shadow-sm border border-gray-200 px-3 py-2 relative">
        <FiKey className="text-gray-400 mr-2 text-lg" />
        <input
          type={showConfirm ? "text" : "password"}
          placeholder="Confirm New Password"
          value={confirmPassword}
          onChange={(e) => setConfirmPassword(e.target.value)}
          className="w-full bg-transparent outline-none text-gray-700 placeholder-gray-400 pr-8"
        />
        <span className="absolute right-3 cursor-pointer text-gray-500" onClick={() => setShowConfirm(!showConfirm)}>
          {showConfirm ? <FiEyeOff /> : <FiEye />}
        </span>
      </div>

      <button
        type="submit"
        disabled={loading}
        className={`w-full ${loading ? "bg-green-400" : "bg-green-500 hover:bg-green-600"} text-white font-semibold px-4 py-2 rounded-lg shadow-md transition duration-300 cursor-pointer`}
      >
        {loading ? "Updating..." : "Change Password"}
      </button>
    </form>
  );
};

export default ChangePasswords;
