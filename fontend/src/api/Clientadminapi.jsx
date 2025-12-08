import Axios from "./Axios";
import config from "../config/config";


export const addClientAdminData = async (formData) => {
  try {
    const res = await Axios.post(`${config.CLIENT_URL}/client_admin`, formData);
    return res.data;
  } catch (error) {
    const message = error.response?.data?.error || error.message;
    throw new Error(message);
  }
};
export const updateClientAdminData = async (user_id, formData) => {
  try {
    const res = await Axios.put(
      `${config.CLIENT_URL}/super_admin_update_client_admin/${user_id}`,
      formData
    );
    return res.data;
  } catch (error) {
    const message = error.response?.data?.error || error.message;
    throw new Error(message);
  }
};


// Delete Client Admin
export const deleteClientAdminData = async (user_id) => {
  try {
    const res = await Axios.delete(
      `${config.CLIENT_URL}/delete_client_admin/${user_id}`
    );
    return res.data;
  } catch (error) {
    const message = error.response?.data?.error || error.message;
    throw new Error(message);
  }
};


export const activateUser = async (user_id) => {
  try {
    const res = await Axios.post(`${config.AUTH_URL}/activate_user/${user_id}`);
    return res.data;
  } catch (error) {
    const message = error.response?.data?.error || error.message;
    throw new Error(message);
  }
};

// ✅ Deactivate Usercls
export const deactivateUser = async (user_id) => {
  try {
    const res = await Axios.post(`${config.AUTH_URL}/deactivate_user/${user_id}`);
    return res.data;
  } catch (error) {
    const message = error.response?.data?.error || error.message;
    throw new Error(message);
  }
};
