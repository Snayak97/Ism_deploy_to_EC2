const config = {
  BASE_URL: String(import.meta.env.VITE_BACKEND_URL),
  AUTH_URL: "/auth",
  USER_URL: "/user",
  CLIENT_URL: "/client",
  CLIENT_USER_URL: "/client_user",
};

export default config;
