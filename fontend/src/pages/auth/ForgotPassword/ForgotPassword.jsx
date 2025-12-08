import React, { useState, useEffect } from "react";
import { AiOutlineArrowLeft } from "react-icons/ai";
import { Link, useNavigate, useLocation } from "react-router-dom";
import { sendForgotMail } from "../../../services/AuthServices";
import { useMutation } from "@tanstack/react-query";

const ForgotPassword = () => {
  const [email, setEmail] = useState("");
  const [serverError, setServerError] = useState("");
  const [successMessage, setSuccessMessage] = useState("");
  const [emailError, setEmailError] = useState("");
  const navigate = useNavigate();
  const location = useLocation();

  useEffect(() => {
    if (location.state?.email) {
      setEmail(location.state.email);
    }
  }, [location.state]);

  const { mutate, isPending } = useMutation({
    mutationKey: ["forgot-email"],
    mutationFn: sendForgotMail,
    onSuccess: (data) => {
      setServerError("");
      const msg = data?.message || "Reset link sent to your email.";
      setSuccessMessage(msg);
      setTimeout(() => {
        if (email) {
          navigate(`/forgot-success/${email}`);
        }
      }, 1500);
    },
    onError: (error) => {
      setSuccessMessage("");
      const message =
        error?.response?.data?.message ||
        error?.response?.data?.error ||
        error.message ||
        "Failed to send reset email.";
      setServerError(message);
    },
  });

  const validateEmail = (value) => {
    if (!value) return "Email is required";
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(value)) return "Email is invalid";
    return "";
  };

  const handleSubmit = (e) => {
    e.preventDefault();
    const emailError = validateEmail(email);
    if (emailError) {
      setEmailError(emailError);
      return;
    }
    mutate({ email });
  };

  return (
    <div className="flex items-center justify-center min-h-screen bg-gray-50">
      <div className="w-full max-w-md bg-white p-6 rounded-xl shadow-lg ">
        <div className="w-fit my-2">
          <Link to="/signin" className="text-gray-500 hover:text-black">
            <AiOutlineArrowLeft className="text-2xl" />
          </Link>
        </div>
        <h1 className="text-3xl font-semibold mb-2 text-center">
          Forgot Password
        </h1>
        {/* Success message */}
        {successMessage && (
          <div
            id="success-message"
            role="alert"
            className="bg-green-200 text-green-700 text-sm break-words whitespace-pre-wrap p-1 rounded-md text-center font-semibold"
          >
            {successMessage}
          </div>
        )}

        {/* Server error message */}
        {serverError && (
          <p
            id="server-error"
            role="alert"
            className="bg-red-200 text-red-700 p-1 text-sm break-words whitespace-pre-wrap rounded-md text-center font-semibold"
          >
            {serverError}
          </p>
        )}
        <p className="text-md text-gray-600 mb-6 text-center">
          Enter your email address to reset your password.
        </p>
        <form onSubmit={handleSubmit} className="space-y-6">
          <div>
            <label
              htmlFor="email"
              className="block text-md placeholder:text-lg font-medium text-gray-700"
            >
              Email
            </label>
            <input
              id="email"
              type="email"
              value={email}
              onChange={(e) => {
                const value = e.target.value;
                setEmail(value);
                if (emailError) setEmailError("");
                if (serverError) setServerError("");
              }}
              className={`mt-1 block w-full px-4 py-2 border rounded-md text-sm shadow-sm focus:outline-none focus:ring-2 focus:ring-blue-500 ${
                emailError ? "border-red-500" : "border-gray-300"
              }`}
              placeholder="Enter your email..."
            />
            {emailError && (
              <p className="text-red-500 text-sm mt-1">{emailError}</p>
            )}
          </div>

          <button
            type="submit"
            disabled={isPending}
            className="w-full bg-blue-600 text-xl font-bold text-white py-2 px-4 rounded-md hover:bg-blue-700 transition"
          >
            {isPending ? "Sending..." : "Reset Password"}
          </button>
        </form>
      </div>
    </div>
  );
};

export default ForgotPassword;
