import { Routes, Route, Navigate } from "react-router-dom";
import { publicRoutes } from "./PublicRoutes";
import { ClientAdminRoutes } from "./ClientAdminRoutes";

const AppRoutes = () => {
  return (
    <Routes>
      <Route path="/" element={<Navigate to="/signin" replace />} />
      {publicRoutes}
      {ClientAdminRoutes}
    </Routes>
  );
};

export default AppRoutes;
