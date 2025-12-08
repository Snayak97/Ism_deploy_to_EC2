import { createContext, useState, useEffect } from "react";
import { logOutUser } from "../services/AuthServices";

export const AuthContext = createContext();

export default function AuthProvider({ children }) {
  const [auth, setAuth] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const accessToken = localStorage.getItem("access_token");
    const refreshToken = localStorage.getItem("refresh_token");
    const user = localStorage.getItem("user");

    if (accessToken && user) {
      setAuth({
        user: JSON.parse(user),
        accessToken,
        refreshToken,
      });
    }
    setLoading(false);
  }, []);

  const login = async (Data) => {
    const { user, accessToken, refreshToken } = Data;
    setAuth({ user, accessToken, refreshToken });
    localStorage.setItem("access_token", accessToken);
    localStorage.setItem("refresh_token", refreshToken);
    localStorage.setItem("user", JSON.stringify(user));
  };

  const logout = async () => {
    setLoading(true);
    try {
      const response = await logOutUser();
      localStorage.removeItem("access_token");
      localStorage.removeItem("refresh_token");
      localStorage.removeItem("user");
      setAuth(null);
      setLoading(false);
      return { success: true, message: response.message || "Logged out" };
    } catch (error) {
      setLoading(false);
      return { success: false, message: error.message || "Logout failed" };
    }
  };

  return (
    <AuthContext.Provider value={{ auth,setAuth, login, logout, loading }}>
      {children}
    </AuthContext.Provider>
  );
}
