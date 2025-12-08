import { FiLogOut } from "react-icons/fi";
import { useNavigate } from "react-router-dom";
import useAuth from "../../../hooks/useAuth";

const LogOut = () => {
  const { logout } = useAuth();
  const navigate = useNavigate();

  const handleLogout = async () => {
    const result = await logout();
    navigate("/signin", { state: { message: result.message } });
  };

  return (
    <button
      onClick={handleLogout}
      className="flex items-center gap-2 bg-red-600 hover:bg-red-700 text-white px-4 py-2 rounded-md shadow-md transition duration-300 cursor-pointer"
    >
      <FiLogOut className="text-lg" />
      Sign out
    </button>
  );
};

export default LogOut;
