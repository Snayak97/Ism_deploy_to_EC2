import React from "react";
import { BsPatchCheckFill } from "react-icons/bs";
import { useParams } from "react-router-dom";

const ForgotPasswordSent = () => {
  const { email } = useParams();

  return (
    <div className="flex items-center justify-center min-h-screen px-4 bg-gray-100">
      <div className="bg-white rounded-lg shadow-lg p-6 md:p-10 w-full max-w-md">
        <div className="flex flex-col items-center space-y-6">
          <BsPatchCheckFill className="text-green-500 text-5xl" />
          <h2 className="text-2xl font-medium text-gray-900">Successfully Sent</h2>
          <p className="text-center text-gray-600 text-md break-words whitespace-pre-wrap">
            We have sent instructions on how to reset your password to{" "}
            <span className="font-semibold text-black">{email}</span>. Please follow
            the instructions from the email.
          </p>
        </div>
      </div>
    </div>
  );
};

export default ForgotPasswordSent;
