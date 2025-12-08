import React, { useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import { useMutation } from "@tanstack/react-query";
import { AiOutlineEye, AiOutlineEyeInvisible } from "react-icons/ai";
import { verfiyForgotToken } from "../../../services/AuthServices";


const ResetPassword = () => {
  const { token } = useParams();
  const navigate = useNavigate();

  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);
  const [errors, setErrors] = useState({});
  const [serverError, setServerError] = useState("");
  const [successMessage, setSuccessMessage] = useState("");
  
  const { mutate, isPending } = useMutation({
    mutationKey: ["verify-forgot-token"],
    mutationFn: verfiyForgotToken,
    onSuccess: (data) => {
      setServerError("");
      const msg = data?.message || "Password reset successfully.";
      setSuccessMessage(msg);
      setTimeout(() => {
        navigate("/reset-success",{ replace: true });
      }, 1500);
    },
    onError: (error) => {
      const message =
        error?.response?.data?.message ||
        error?.response?.data?.error ||
        error.message ||
        "Failed to reset password.";
      setServerError(message);
    },
  });

  const validate = () => {
    const newErrors = {};
    if (!password || password.length < 6) {
      newErrors.password = "Password must be at least 6 characters";
    }
    if (confirmPassword !== password) {
      newErrors.confirmPassword = "Passwords must match";
    }
    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  const handleSubmit = (e) => {
    e.preventDefault();
    if (!validate()) return;
    mutate({ token, new_password: password });
  };

  return (
    <div className="flex items-center justify-center min-h-screen bg-gray-50">
      <div className="w-full max-w-md bg-white p-6 rounded-xl shadow-lg">
        <h1 className="text-3xl font-semibold mb-2 text-center">Reset Password</h1>

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

        <form onSubmit={handleSubmit} className="space-y-6">
          <div className="relative">
            <label htmlFor="password" className="block text-md font-medium text-gray-700">
              New Password
            </label>
            <input
              id="password"
              type={showPassword ? "text" : "password"}
              value={password}
              onChange={(e) => {
                setPassword(e.target.value);
                if (errors.password) setErrors((prev) => ({ ...prev, password: "" }));
              }}
              placeholder="Enter new password..."
              className={`mt-1 w-full px-4 py-2 border rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 ${
                errors.password ? "border-red-500" : "border-gray-300"
              }`}
            />
            <span
              onClick={() => setShowPassword((prev) => !prev)}
              className="absolute right-3 top-[40px] cursor-pointer text-gray-600"
            >
              {showPassword ? <AiOutlineEyeInvisible size={20} /> : <AiOutlineEye size={20} />}
            </span>
            {errors.password && (
              <p className="text-red-500 text-sm mt-1">{errors.password}</p>
            )}
          </div>

          <div className="relative">
            <label
              htmlFor="confirmPassword"
              className="block text-md font-medium text-gray-700"
            >
              Confirm Password
            </label>
            <input
              id="confirmPassword"
              type={showConfirmPassword ? "text" : "password"}
              value={confirmPassword}
              onChange={(e) => {
                setConfirmPassword(e.target.value);
                if (errors.confirmPassword) setErrors((prev) => ({ ...prev, confirmPassword: "" }));
              }}
              placeholder="Repeat new password..."
              className={`mt-1 w-full px-4 py-2 border rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 ${
                errors.confirmPassword ? "border-red-500" : "border-gray-300"
              }`}
            />
            <span
              onClick={() => setShowConfirmPassword((prev) => !prev)}
              className="absolute right-3 top-[40px] cursor-pointer text-gray-600"
            >
              {showConfirmPassword ? (
                <AiOutlineEyeInvisible size={20} />
              ) : (
                <AiOutlineEye size={20} />
              )}
            </span>
            {errors.confirmPassword && (
              <p className="text-red-500 text-sm mt-1">{errors.confirmPassword}</p>
            )}
          </div>

          <button
            type="submit"
            disabled={isPending}
            className="w-full bg-blue-600 text-xl font-bold text-white py-2 px-4 rounded-md hover:bg-blue-700 transition"
          >
            {isPending ? "Resetting..." : "Reset Password"}
          </button>
        </form>
      </div>
    </div>
  );
};

export default ResetPassword;








// import React, { useState } from "react";
// import { useNavigate, useParams } from "react-router-dom";
// import { verfiyForgotToken } from "../../../api/query/user_query";
// import { useMutation } from "@tanstack/react-query";

// const ResetPassword = () => {
//   const { token } = useParams();
//   const navigate = useNavigate();

//   const [password, setPassword] = useState("");
//   const [ConfirmPassword, setConfirmPassword] = useState("");
//   const [errors, setErrors] = useState({});
  
// //   const { mutate, isLoading } = useMutation({
// //     mutationKey: ["verify-forgot-token"],
// //     mutationFn: verfiyForgotToken,
// //     enabled: !!token,
// //     onError: (error) => {
// //       alert(error.message);
// //       navigate("/signup");
// //     },
// //     onSettled: () => {
// //       navigate("/reset-success");
// //     },
// //   });

//   const validate = () => {
//     const newErrors = {};
//     if (!password || password.length < 6) {
//       newErrors.password = "Password must be at least 6 characters";
//     }
//     if (ConfirmPassword !== password) {
//       newErrors.ConfirmPassword = "Passwords must match";
//     }
//     setErrors(newErrors);
//     return Object.keys(newErrors).length === 0;
//   };

//   const handleSubmit = (e) => {
//     e.preventDefault();
//     if (!validate()) return;
//     mutate({ token, password });
//   };

// //   if (true) {
// //     return (
// //       <div className="flex items-center justify-center h-screen">
// //         <div className="h-12 w-12 border-4 border-purple-500 border-t-transparent rounded-full animate-spin"></div>
// //       </div>
// //     );
// //   }

//   return (
//     <div className="flex items-center justify-center min-h-screen bg-gray-100 px-4">
//       <div className="bg-white rounded-lg shadow-lg p-8 w-full max-w-md">
//         <h1 className="text-3xl text-center font-semibold text-gray-800">Reset Password</h1>
//         <p className="text-md text-center text-gray-600 mt-2 mb-6">Enter your new password.</p>

//         <form onSubmit={handleSubmit} className="space-y-6">
//           <div>
//             <label
//               htmlFor="password"
//               className="block text-md font-medium text-gray-700"
//             >
//               New Password
//             </label>
//             <input
//               id="password"
//               type="password"
//               value={password}
//               onChange={(e) => setPassword(e.target.value)}
//               placeholder="Enter new password..."
//               className={`mt-1 w-full px-4 py-2 border rounded-md focus:outline-none focus:ring-2 focus:ring-purple-500 ${
//                 errors.password ? "border-red-500" : "border-gray-300"
//               }`}
//             />
//             {errors.password && (
//               <p className="text-red-500 text-sm mt-1">{errors.password}</p>
//             )}
//           </div>

//           <div>
//             <label
//               htmlFor=" ConfirmPassword"
//               className="block text-md font-medium text-gray-700"
//             >
//                ConfirmPassword
//             </label>
//             <input
//               id=" ConfirmPassword"
//               type="password"
//               value={ ConfirmPassword}
//               onChange={(e) => setConfirmPassword(e.target.value)}
//               placeholder="Repeat new password..."
//               className={`mt-1 w-full px-4 py-2 border rounded-md focus:outline-none focus:ring-2 focus:ring-purple-500 ${
//                 errors. ConfirmPassword ? "border-red-500" : "border-gray-300"
//               }`}
//             />
//             {errors.ConfirmPassword && (
//               <p className="text-red-500 text-sm mt-1">{errors.ConfirmPassword}</p>
//             )}
//           </div>

//           <button
//             type="submit"
//             className="w-full bg-blue-600 text-2xl font-bold hover:bg-blue-700 py-2 px-4 rounded-md text-white transition"
//           >
//             Reset Password
//           </button>
//         </form>
//       </div>
//     </div>
//   );
// };

// export default ResetPassword;
