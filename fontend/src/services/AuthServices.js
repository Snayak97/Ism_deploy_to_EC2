import Axios from "../api/Axios.js";
import config from "../config/config";

export const signupUser = async (formData) => {
  try {
    const res = await Axios.post(`${config.USER_URL}/signup`, formData);
    return res.data;
  } catch (error) {
    const message = error.response?.data?.error || error.message;
    throw new Error(message);
  }
};

export const sendVerificationMail = async (email) => {
  try {
    const res = await Axios.post(
      `${config.USER_URL}/resend-verification`,
      email
    );
    return res.data;
  } catch (error) {
    const message = error.response?.data?.error || error.message;
    throw new Error(message);
  }
};

export const sendForgotMail = async ({ email }) => {
  try {
    const res = await Axios.post(`${config.AUTH_URL}/forgot-password`, {
      email,
    });
    return res.data;
  } catch (error) {
    const message = error.response?.data?.error || error.message;
    throw new Error(message);
  }
};

export const verfiyEmailAddressSignup = async (token) => {
  try {
    const res = await Axios.get(`${config.USER_URL}/verify-email/${token}`);
    return res.data;
  } catch (error) {
    const message = error.response?.data?.error || error.message;
    throw new Error(message);
  }
};

export const verfiyForgotToken = async ({ token, new_password }) => {
  try {
    const res = await Axios.post(`${config.AUTH_URL}/reset-password`, {
      token,
      new_password,
    });
    return res.data;
  } catch (error) {
    const message = error.response?.data?.error || error.message;
    throw new Error(message);
  }
};

export const signinUser = async (formData) => {
  try {
    const res = await Axios.post(`${config.AUTH_URL}/login`, formData);
    const {
      user,
      access_token: accessToken,
      refresh_token: refreshToken,
      message,
      force_reset_password,
    } = res.data;
    localStorage.setItem("access_token", accessToken);
    localStorage.setItem("refresh_token", refreshToken);
    localStorage.setItem("user", JSON.stringify(user));

    return { user, accessToken, refreshToken, message, force_reset_password };
  } catch (error) {
    const message = error.response?.data?.error || error.message;
    throw new Error(message);
  }
};

export const logOutUser = async () => {
  try {
    const res = await Axios.post(`${config.AUTH_URL}/logout`);
    console.log("[logOutUser] Response:", res.data);

    return res.data;
  } catch (error) {
    const message = error.response?.data?.error || error.message;
    throw new Error(message);
  }
};


export const updateUserProfile = async (userId, formData) => {
  try {

    const res = await Axios.put(
      `${config.USER_URL}/update_user/${userId}`,
      formData
    );

    const {user,message} = res.data;


    localStorage.setItem("user", JSON.stringify(user));

    return {user,message};
  } catch (error) {
    const message = error.response?.data?.error || error.message;
    throw new Error(message);
  }
};

export const changePassword = async (formData) => {
  try {
    const res = await Axios.post(`${config.AUTH_URL}/change_password`, formData);
    return { message: res.data.message };
  } catch (error) {
    const message = error.response?.data?.error || error.message;
    throw new Error(message);
  }
};

export const deleteNormalUser = async (user_id) => {
  try {
    const res = await Axios.delete(`${config.USER_URL}/delete_user/${user_id}`);
    return res.data;
  } catch (error) {
    const message = error.response?.data?.error || error.message;
    throw new Error(message);
  }
};