import { useNavigate } from "react-router-dom";
import { useMutation } from "@tanstack/react-query";
import { sendForgotMail } from "../../services/AuthServices";
import useAuth from "../../hooks/useAuth";
import React, { useState, useEffect } from "react";
import { FiMail } from "react-icons/fi";

const RecoveryPasswords = () => {
  const { auth } = useAuth();
  const navigate = useNavigate();
  const user = auth?.user;

  // --- Recovery Password States ---
  const [email, setEmail] = useState("");
  const [emailError, setEmailError] = useState("");
  const [serverError, setServerError] = useState("");
  const [successMessage, setSuccessMessage] = useState("");

  // --- Set user email dynamically ---
  useEffect(() => {
    if (user?.email) setEmail(user.email);
  }, [user]);

  // --- Validate Email ---
  const validateEmail = (value) => {
    if (!value) return "Email is required";
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(value)) return "Email is invalid";
    return "";
  };

  // --- Recovery Mail Mutation ---
  const { mutate: sendRecoveryMail, isLoading: recoveryLoading } = useMutation({
    mutationFn: sendForgotMail,
    onSuccess: (data) => {
      setServerError("");
      const msg = data?.message || "Recovery instructions sent!";
      setSuccessMessage(msg);

      // optional redirect after 1.5s
      setTimeout(() => {
        if (email) navigate(`/forgot-success/${email}`);
      }, 1500);
    },
    onError: (error) => {
      setSuccessMessage("");
      const message =
        error?.response?.data?.message ||
        error?.response?.data?.error ||
        error.message ||
        "Failed to send recovery email.";
      setServerError(message);
    },
  });

  const handleRecoverySubmit = (e) => {
    e.preventDefault();
    const error = validateEmail(email);
    if (error) {
      setEmailError(error);
      return;
    }
    sendRecoveryMail({ email });
  };

  return (
    <>
   
      <div className="p-6 bg-gradient-to-r from-blue-50 to-blue-100 shadow-xl rounded-2xl border border-blue-200 dark:shadow-md dark:bg-gradient-to-r dark:from-gray-800 dark:to-gray-900 dark:text-white hover:scale-101 transition transform duration-300 ease-in-out  dark:hover:border-gray-300 dark:hover:shadow-[0_0_10px_2px_rgba(255,255,255,0.7)]">
        <h3 className="text-xl font-semibold mb-6 text-blue-700 text-center">
          Recovery Password Email
        </h3>

        {/* Success & Server Error */}
        {successMessage && (
          <p className="bg-green-200 text-green-700 text-sm p-2 rounded-md text-center font-medium mb-3">
            {successMessage}
          </p>
        )}
        {serverError && (
          <p className="bg-red-200 text-red-700 text-sm p-2 rounded-md text-center font-medium mb-3">
            {serverError}
          </p>
        )}

        {/* Recovery Form */}
        <form onSubmit={handleRecoverySubmit} className="space-y-4 ">
          <div className="flex items-center mb-3 bg-white rounded-lg shadow-sm border border-gray-200 px-3 py-2 ">
            <FiMail className="text-gray-400 mr-2 text-lg" />
            <input
              type="email"
              placeholder="Enter your recovery email"
              value={email}
              onChange={(e) => {
                setEmail(e.target.value);
                if (emailError) setEmailError("");
                if (serverError) setServerError("");
              }}
              className={`w-full bg-transparent outline-none text-gray-700 placeholder-gray-400 ${
                emailError ? "border-red-500" : ""
              }`}
            />
          </div>
          {emailError && <p className="text-red-500 text-sm">{emailError}</p>}

          {/* <button
            type="submit"
            disabled={recoveryLoading}
            className="w-full bg-blue-500 mt-3 cursor-pointer hover:bg-blue-600 text-white font-semibold px-4 py-2 rounded-lg shadow-md transition duration-300"
          >
            {recoveryLoading ? "Sending..." : "Send Recovery Email"}
          </button> */}
        </form>
      </div>
    </>
  );
};

export default RecoveryPasswords;
