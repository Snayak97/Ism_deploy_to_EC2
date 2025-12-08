import { useState } from "react";
import { useNavigate, Link } from "react-router-dom";
import { AiOutlineArrowLeft } from "react-icons/ai";
import accurest_logo from "../../../assets/accurest_logo.svg";
import { useMutation } from "@tanstack/react-query";
import { signupUser } from "../../../services/AuthServices";

const Signup = () => {
  const [form, setForm] = useState({
    username: "",
    email: "",
    password: "",
    mobile_number: "",
    department: "",
  });

  const [errors, setErrors] = useState({});
  const [serverError, setServerError] = useState("");
  const [successMessage, setSuccessMessage] = useState("");
  const navigate = useNavigate();

  const { mutate, isPending } = useMutation({
    mutationKey: ["signup"],
    mutationFn: signupUser,
    onSuccess: (data) => {
      setServerError("");
      const msg =
        data?.message ||
        "Register Verification Link sent to your registered email. Please verify it.";
      setSuccessMessage(msg);

      setTimeout(() => {
        if (form.email) {
          navigate(`/RegisterEmailVerify/${encodeURIComponent(form.email)}`);
        }
      }, 1000);
    },
    onError: (error) => {
      setSuccessMessage("");
      const message =
        error?.response?.data?.message || error.message || "Register Failed";
      setServerError(message);
    },
  });

  const validateField = (name, value) => {
    switch (name) {
      case "username":
        return value.trim() === "" ? "Username is required" : "";
      case "email":
        return !value.includes("@") ? "Valid email required" : "";
      case "password":
        return value.length < 6 ? "Password must be at least 6 characters" : "";
      case "mobile_number":
        return /^\d{10}$/.test(value) ? "" : "Mobile number must be 10 digits";
      case "department":
        return value.trim() === "" ? "Department is required" : "";
      default:
        return "";
    }
  };

  const validateAll = () => {
    const newErrors = {};
    Object.keys(form).forEach((key) => {
      const error = validateField(key, form[key]);
      if (error) newErrors[key] = error;
    });
    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  const handleChange = (e) => {
    const { name, value } = e.target;

    setForm((prev) => ({ ...prev, [name]: value }));

    const fieldError = validateField(name, value);
    setErrors((prev) => ({ ...prev, [name]: fieldError }));

    // Clear server and success messages when user modifies input
    if (serverError) setServerError("");
    if (successMessage) setSuccessMessage("");
  };

  const handleSubmit = (e) => {
    e.preventDefault();
    if (!validateAll()) return;
    mutate(form);
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-100">
      <form
        onSubmit={handleSubmit}
        className="bg-white p-8 rounded-lg shadow-md w-full max-w-md space-y-4"
      >
        <div className="flex items-center justify-between w-full mb-6">
          <Link to="/signin" className="text-gray-500 hover:text-black">
            <AiOutlineArrowLeft className="text-2xl" />
          </Link>

          <div className="absolute left-1/2 transform -translate-x-1/2">
            <img src={accurest_logo} alt="Logo" className="h-12 w-auto" />
          </div>
        </div>

        <h1 className="text-center text-2xl font-semibold">
          Create a new account
        </h1>
        <p className="text-sm text-gray-600 -mt-[20px] text-center">
          It's quick and easy.
        </p>
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

        {/** Username */}
        <div>
          <label className="block mb-1 font-medium">Username</label>
          <input
            name="username"
            type="text"
            className="w-full border border-gray-300 p-2 rounded"
            value={form.username}
            onChange={handleChange}
          />
          {errors.username && (
            <p className="text-red-500 text-sm">{errors.username}</p>
          )}
        </div>

        {/** Email */}
        <div>
          <label className="block mb-1 font-medium">Email</label>
          <input
            name="email"
            type="email"
            className="w-full border border-gray-300 p-2 rounded"
            value={form.email}
            onChange={handleChange}
          />
          {errors.email && (
            <p className="text-red-500 text-sm">{errors.email}</p>
          )}
        </div>

        {/** Password */}
        <div>
          <label className="block mb-1 font-medium">Password</label>
          <input
            name="password"
            type="password"
            className="w-full border border-gray-300 p-2 rounded"
            value={form.password}
            onChange={handleChange}
          />
          {errors.password && (
            <p className="text-red-500 text-sm">{errors.password}</p>
          )}
        </div>

        {/** Mobile Number */}
        <div>
          <label className="block mb-1 font-medium">Mobile Number</label>
          <input
            name="mobile_number"
            type="text"
            className="w-full border border-gray-300 p-2 rounded"
            value={form.mobile_number}
            onChange={handleChange}
          />
          {errors.mobile_number && (
            <p className="text-red-500 text-sm">{errors.mobile_number}</p>
          )}
        </div>

        {/** Department */}
        <div>
          <label className="block mb-1 font-medium">Department</label>
          <input
            name="department"
            type="text"
            className="w-full border border-gray-300 p-2 rounded"
            value={form.department}
            onChange={handleChange}
          />
          {errors.department && (
            <p className="text-red-500 text-sm">{errors.department}</p>
          )}
        </div>

        <button
          type="submit"
          className="w-full bg-purple-600 text-2xl font-bold text-white p-2 rounded hover:bg-green-700 transition"
        >
          Sign Up
        </button>
      </form>
    </div>
  );
};

export default Signup;
