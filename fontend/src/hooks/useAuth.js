import { useContext } from "react";
import { AuthContext } from "../context/Auth";

const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error("useAuth must be used within AuthProvider");
  }

  const { auth, setAuth, login, logout, loading } = context;
  return { auth, setAuth, login, logout, loading };
};

export default useAuth;
