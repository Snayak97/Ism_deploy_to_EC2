import React, { useState, useEffect } from "react";
import { useLocation, useNavigate, Link } from "react-router-dom";
import accurest_logo from "../../../assets/accurest_logo.svg";
import { useMutation } from "@tanstack/react-query";
import { signinUser } from "../../../services/AuthServices";
import useAuth from "../../../hooks/useAuth";

const Signin = () => {
  const [form, setForm] = useState({ email: "", password: "" });
  const [errors, setErrors] = useState({});
  const [serverError, setServerError] = useState("");
  const [successMessage, setSuccessMessage] = useState("");
  const navigate = useNavigate();
  const { login } = useAuth();
  const location = useLocation();

  useEffect(() => {
    if (location.state?.message) {
      setSuccessMessage(location.state.message);
      navigate(location.pathname, { replace: true });

      const timer = setTimeout(() => setSuccessMessage(""), 3000);
      return () => clearTimeout(timer);
    }
  }, [location, navigate]);

  useEffect(() => {
    if (serverError) {
      const timer = setTimeout(() => setServerError(""), 3000);
      return () => clearTimeout(timer);
    }
  }, [serverError]);

  useEffect(() => {
    if (successMessage) {
      const timer = setTimeout(() => setSuccessMessage(""), 3000);
      return () => clearTimeout(timer);
    }
  }, [successMessage]);

  const { mutate, isPending } = useMutation({
    mutationKey: ["signin"],
    mutationFn: signinUser,
    onSuccess: (data) => {
      setServerError("");
      const msg = data?.message || "Login successful! Redirecting...";
      setSuccessMessage(msg);
      login(data);

      const accessToken = localStorage.getItem("access_token");
      let redirectTo = "";

      if (data.user.role_name === "normal_user") {
        redirectTo = "/clientadmin/dashboard";
      } else if (data.user.role_name === "manager") {
        if (data.force_reset_password) {
          redirectTo = `/forgot-password-verify/${accessToken}`;
        } else {
          redirectTo = "/clientadmin/dashboard";
        }
      } else if (data.user.role_name === "employee") {
        if (data.force_reset_password) {
          redirectTo = `/forgot-password-verify/${accessToken}`;
        } else {
          redirectTo = "/clientadmin/dashboard";
        }
      } else if (data.user.role_name === "client_admin") {
        if (data.force_reset_password) {
          redirectTo = `/forgot-password-verify/${accessToken}`;
        } else {
          redirectTo = "/clientadmin/dashboard";
        }
      } else if (data.user.role_name === "super_admin") {
        // redirectTo = "/superadminpages";
         redirectTo = "/clientadmin/dashboard";
      }
      setTimeout(() => {
        navigate(redirectTo, { replace: true });
      }, 1500);
    },
    onError: (error) => {
      setSuccessMessage("");
      const message =
        error?.response?.data?.message || error.message || "Login failed";
      setServerError(message);
    },
  });

  const validateField = (name, value) => {
    switch (name) {
      case "email":
        if (!value) return "Email is required";
        if (!value.includes("@")) return "Valid email required";
        return "";
      case "password":
        if (!value) return "Password is required";
        if (value.length < 6) return "Password must be at least 6 characters";
        return "";
      default:
        return "";
    }
  };

  const validateAll = () => {
    const newErrors = {};
    Object.entries(form).forEach(([key, value]) => {
      const error = validateField(key, value);
      if (error) newErrors[key] = error;
    });
    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  const handleChange = (e) => {
    const { name, value } = e.target;
    setForm((prev) => ({ ...prev, [name]: value }));
    setErrors((prev) => ({ ...prev, [name]: validateField(name, value) }));

    if (serverError) setServerError("");
    if (successMessage) setSuccessMessage("");
  };

  const handleSubmit = (e) => {
    e.preventDefault();
    if (!validateAll()) return;
    mutate(form);
  };

  return (
    <div className="min-h-screen  flex items-center justify-center bg-gray-100 p-4">
      <form
        onSubmit={handleSubmit}
        className="bg-white p-8 rounded-lg shadow-md w-full max-w-md space-y-6"
        noValidate
        aria-describedby="server-error success-message"
      >
        <div className="flex flex-col items-center">
          <img
            src={accurest_logo}
            alt="Accurest Logo"
            className="h-12 w-auto mb-0"
          />
        </div>

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

        {/* Email input */}
        <div>
          <label
            htmlFor="email"
            className="block mb-1 font-semibold text-gray-700"
          >
            Email
          </label>
          <input
            id="email"
            name="email"
            type="email"
            value={form.email}
            onChange={handleChange}
            className={`w-full p-3 rounded-md border ${
              errors.email ? "border-red-500" : "border-gray-300"
            } focus:outline-none focus:ring-2 focus:ring-purple-500`}
            placeholder="Enter your email"
            aria-invalid={errors.email ? "true" : "false"}
            aria-describedby={errors.email ? "email-error" : undefined}
            required
          />
          {errors.email && (
            <p
              id="email-error"
              className="text-red-500 text-sm mt-1"
              role="alert"
            >
              {errors.email}
            </p>
          )}
        </div>

        {/* Password input */}
        <div>
          <label
            htmlFor="password"
            className="block mb-1 font-semibold text-gray-700"
          >
            Password
          </label>
          <input
            id="password"
            name="password"
            type="password"
            value={form.password}
            autoComplete="password"
            onChange={handleChange}
            className={`w-full p-3 rounded-md border ${
              errors.password ? "border-red-500" : "border-gray-300"
            } focus:outline-none focus:ring-2 focus:ring-purple-500 transition duration-150 ease-in-out`}
            placeholder="Enter your password"
            aria-invalid={errors.password ? "true" : "false"}
            aria-describedby={errors.password ? "password-error" : undefined}
            required
          />
          {errors.password && (
            <p
              id="password-error"
              className="text-red-500 text-sm mt-1"
              role="alert"
            >
              {errors.password}
            </p>
          )}
        </div>

        {/* Remember me and forgot password */}
        <div className="flex items-center justify-between text-sm">
          <label className="flex items-center">
            <input type="checkbox" className="mr-2" aria-label="Remember me" />
            Remember me
          </label>
          <Link
            to="/forgotpassword"
            state={{ email: form.email }}
            className="text-purple-600 hover:underline"
          >
            Forgot password?
          </Link>
        </div>

        {/* Submit Button */}
        <button
          type="submit"
          disabled={isPending}
          className={`w-full bg-blue-600 text-white text-2xl font-bold py-3 rounded-md hover:bg-blue-700 transition duration-200 ${
            isPending ? "opacity-50 cursor-not-allowed" : ""
          }`}
          aria-busy={isPending}
        >
          {isPending ? "Logging in..." : "Log in"}
        </button>

        <p className="text-center text-sm mt-4">
          Don't have an account?{" "}
          <Link to="/signup" className="text-purple-600 hover:underline">
            Sign up
          </Link>
        </p>
      </form>
    </div>
  );
};

export default Signin;
