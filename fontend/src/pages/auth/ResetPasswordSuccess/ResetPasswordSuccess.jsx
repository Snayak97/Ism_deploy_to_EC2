import React, { useEffect } from "react";
import { BsPatchCheckFill } from "react-icons/bs";
import { Link,useNavigate } from "react-router-dom";

const ResetPasswordSuccess = () => {
  // const navigate = useNavigate();
  // useEffect(() => {
  //   // Replace current history to prevent going back
  //   navigate(window.location.pathname, { replace: true });

  //   // Optional: Hard block back navigation
  //   const blockBack = () => {
  //     window.history.pushState(null, "", window.location.href);
  //   };

  //   window.history.pushState(null, "", window.location.href);
  //   window.addEventListener("popstate", blockBack);

  //   return () => {
  //     window.removeEventListener("popstate", blockBack);
  //   };
  // }, [navigate]);

  return (
    <div className="flex items-center justify-center min-h-screen bg-gray-100 px-4">
      <div className="bg-white p-10 rounded-lg shadow-md max-w-md w-full text-center space-y-6">
        <BsPatchCheckFill className="mx-auto text-green-500" size={48} />
        <h2 className="text-2xl font-medium text-gray-900">
          Password Reset Done
        </h2>
        <p className="text-gray-600">Now you can access your account.</p>
        <Link to="/signin" className="block">
          <button className="w-full bg-blue-600 text-2xl font-bold hover:bg-blue-700 text-white py-2 rounded-md transition">
            Log in
          </button>
        </Link>
      </div>
    </div>
  );
};

export default ResetPasswordSuccess;
