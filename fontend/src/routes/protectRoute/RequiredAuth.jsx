import React from "react";

import { Navigate, useLocation } from "react-router-dom";
import useAuth from "../../hooks/useAuth";

const RequireAuth = ({ children }) => {
  const { auth, loading } = useAuth();
  const location = useLocation();
  if (loading) {
    return null;
  }

  if (!auth?.accessToken) {
    return <Navigate to="/signin" state={{ from: location }} replace />;
  }

  return children;
};

export default RequireAuth;
