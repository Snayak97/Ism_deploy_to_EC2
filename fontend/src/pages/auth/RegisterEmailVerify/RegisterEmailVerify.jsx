import React, { useEffect, useState } from "react";
import { MdEmail } from "react-icons/md";
import { useParams, useNavigate } from "react-router-dom";
import { useMutation } from "@tanstack/react-query";

import { sendVerificationMail } from "../../../services/AuthServices";

const RegisterEmailVerify = () => {
  const { email } = useParams();
  const [serverError, setServerError] = useState("");
  const [successMessage, setSuccessMessage] = useState("");
  const navigate = useNavigate();

  const { mutate, isPending } = useMutation({
    mutationKey: ["sendVerificationMail"],
    mutationFn: sendVerificationMail,
    onSuccess: (data) => {
      setServerError("");
      const msg =
        data?.message ||
        "Register Verification Link Re-sent to your registered email. Please verify it.";
      setSuccessMessage(msg);
      // setTimeout(() => {
      //   // if (email) {
      //   //   // navigate(`/`);
      //   //   console.log("Hello")
      //   // }
      // }, 1000);
    },
    onError: (error) => {
      setSuccessMessage("");
      const message =
        error?.response?.data?.message || error.message || "Emailsent Failed";
      setServerError(message);
    },
  });

  //   useEffect(() => {
  //     if (email) mutate({ email });
  //   }, [email]);

  if (!email) {
    return (
      <div className="flex items-center justify-center h-screen text-red-500 font-medium">
        Invalid Email
      </div>
    );
  }

  return (
    <div className="flex items-center justify-center min-h-screen px-4  bg-gray-100">
      <div className="bg-white rounded-lg shadow-lg p-6 md:p-10 w-full max-w-md">
        <div className="flex flex-col items-center space-y-6">
          <MdEmail className="text-purple-600 text-5xl" />
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
          <h2 className="text-2xl font-medium text-gray-900">
            Email Verification
          </h2>
          <p className="text-center text-md text-gray-600  break-words whitespace-pre-wrap ">
            We have sent you an email verification to{" "}
            <span className="font-semibold text-black">{email}</span>. <br />
            If you didn’t receive it, click the button below.
          </p>

          <button
            onClick={() => {
              setServerError("");
              setSuccessMessage("");
              mutate({ email });
            }}
            disabled={isPending}
            className="w-full border bg-purple-600 text-2xl font-bold text-white border-purple-600  hover:bg-purple-700 px-4 py-2 rounded-md transition duration-200 disabled:opacity-50"
          >
            {isPending ? "Sending..." : "Re-Send Email"}
          </button>
        </div>
      </div>
    </div>
  );
};

export default RegisterEmailVerify;
