import React from "react";
import { BsPatchCheckFill } from "react-icons/bs";
import { Link, useNavigate, useParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";

import { verfiyEmailAddressSignup } from "../../../services/AuthServices";

const RegisterSuccess = () => {
  const { token } = useParams();
  const navigate = useNavigate();

  const { isSuccess, isLoading, isError, error } = useQuery({
    queryKey: ["verify-email", token],
    queryFn: () => verfiyEmailAddressSignup(token),
    enabled: !!token,
    onError: (err) => {
      alert(`Email verification failed: ${err.message}`);
      navigate("/signup");
    },
  });

  if (isLoading) {
    return (
      <div className="flex items-center justify-center min-h-screen">
        <svg
          className="animate-spin h-10 w-10 text-purple-600"
          xmlns="http://www.w3.org/2000/svg"
          fill="none"
          viewBox="0 0 24 24"
        >
          <circle
            className="opacity-25"
            cx="12"
            cy="12"
            r="10"
            stroke="currentColor"
            strokeWidth="4"
          ></circle>
          <path
            className="opacity-75"
            fill="currentColor"
            d="M4 12a8 8 0 018-8v8H4z"
          ></path>
        </svg>
      </div>
    );
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-100 px-4">
      {isSuccess && (
        <div className="bg-white p-10 rounded-xl shadow-lg max-w-md w-full text-center">
          <div className="flex justify-center mb-6">
            <BsPatchCheckFill className="text-green-500 w-12 h-12" />
          </div>
          <h2 className="text-2xl font-medium text-black mb-4">
            Email Verified Successfully!
          </h2>
          <p className="text-gray-600 mb-8">
            Your email has been verified. You can now log in and explore all the
            features.
          </p>
          <Link to="/signin">
            <button className="w-full bg-purple-600 text-2xl font-bold text-white py-3 rounded-md hover:bg-purple-700 transition duration-200">
              Enter the app
            </button>
          </Link>
        </div>
      )}
    </div>
  );
};

export default RegisterSuccess;

// import React from "react";
// import { BsPatchCheckFill } from "react-icons/bs";
// import { Link, useNavigate, useParams } from "react-router-dom";
// import { useQuery } from "@tanstack/react-query";

// import { verfiyEmailAddressSignup } from "../../../api/query/user_query";

// const RegisterSuccess = () => {
//   const { token } = useParams();
//   const navigate = useNavigate();
//   console.log(token);

// //   const { isSuccess, isLoading } = useQuery({
// //     // queryKey: ["verify-email-token"],
// //     // queryFn: () => verfiyEmailAddressSignup({ token }),
// //     // enabled: !!token,
// //     onError: (error) => {
// //       alert(`SignUp Error: ${error.message}`);
// //       navigate("/signup");
// //     },
// //   });

//   if (false)
//     return (
//       <div className="flex items-center justify-center min-h-screen">
//         <svg
//           className="animate-spin h-10 w-10 text-purple-600"
//           xmlns="http://www.w3.org/2000/svg"
//           fill="none"
//           viewBox="0 0 24 24"
//         >
//           <circle
//             className="opacity-25"
//             cx="12"
//             cy="12"
//             r="10"
//             stroke="currentColor"
//             strokeWidth="4"
//           ></circle>
//           <path
//             className="opacity-75"
//             fill="currentColor"
//             d="M4 12a8 8 0 018-8v8H4z"
//           ></path>
//         </svg>
//       </div>
//     );

//   return (
//     <div className="min-h-screen flex items-center justify-center bg-gray-100 px-4">
//       {true && (
//         <div className="bg-white p-10 rounded-xl shadow-lg max-w-md w-full text-center">
//           <div className="flex justify-center mb-6">
//             <BsPatchCheckFill className="text-green-500 w-12 h-12" />
//           </div>
//           <h2 className="text-2xl font-medium text-black mb-4">
//             Successfully Registered
//           </h2>
//           <p className="text-gray-600 mb-8">
//             Hurray! You have successfully created your account. Enter the app to
//             explore all its features.
//           </p>
//           <Link to="/signin">
//             <button className="w-full bg-purple-600 text-2xl font-bold text-white py-3 rounded-md  hover:bg-purple-700 transition duration-200">
//               Enter the app
//             </button>
//           </Link>
//         </div>
//       )}
//     </div>
//   );
// };

// export default RegisterSuccess;
