import { useMutation } from "@tanstack/react-query";
import { getClientUsersData } from "../api/ClientuserApi/ClientUserapi";

export const useClientsData = () => {
  return useMutation({
    mutationFn: getClientUsersData,
  });
};