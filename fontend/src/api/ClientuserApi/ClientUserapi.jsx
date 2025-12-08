import Axios from "../Axios";
import config from "../../config/config";


export const getClientUsersData = async () => {
  try {
    const res = await Axios.get(`${config.CLIENT_USER_URL}/list_client_users`);
    return res.data;
  } catch (error) {
    const message = error.response?.data?.error || error.message;
    throw new Error(message);
  }
};

export const addClientUserData = async (formData) => {
  try {
    const res = await Axios.post(`${config.CLIENT_USER_URL}/create_client_user`, formData);
    return res.data;
  } catch (error) {
    const message = error.response?.data?.error || error.message;
    throw new Error(message);
  }
};
export const updateClientUserData = async (user_id, formData) => {
  try {
    const res = await Axios.put(
      `${config.CLIENT_USER_URL}/update_client_user/${user_id}`,
      formData
    );
    return res.data;
  } catch (error) {
    const message = error.response?.data?.error || error.message;
    throw new Error(message);
  }
};


// Delete Client Admin
export const deleteClientUserData = async (user_id) => {
  try {
    const res = await Axios.delete(
      `${config.CLIENT_USER_URL}/delete_client_user/${user_id}`
    );
    return res.data;
  } catch (error) {
    const message = error.response?.data?.error || error.message;
    throw new Error(message);
  }
};