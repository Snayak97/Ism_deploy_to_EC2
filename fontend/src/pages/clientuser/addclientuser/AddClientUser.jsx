import React, { useState, useEffect } from "react";
import {
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  TextField,
  Button,
  Alert,
  CircularProgress,
  MenuItem,
} from "@mui/material";
import { useMutation } from "@tanstack/react-query";
import {
  addClientUserData,
  updateClientUserData,
} from "../../../api/ClientuserApi/ClientUserapi";

const AddClientUser = ({ open, onClose, onSuccess, editData }) => {
  const [form, setForm] = useState({
    user_name: "",
    email: "",
    mobile_number: "",
    role_name: "",
    department_name: "",
  });

  const [errors, setErrors] = useState({});
  const [serverError, setServerError] = useState("");
  const [successMessage, setSuccessMessage] = useState("");

  // Prefill form for editing
  useEffect(() => {
    if (editData) {
      setForm({
        user_name: editData.user_name || "",
        email: editData.email || "",
        mobile_number: editData.mobile_number || "",
        role_name: editData.role_name || "",
        department_name: editData.department_name || "",
      });
    } else {
      setForm({
        user_name: "",
        email: "",
        mobile_number: "",
        role_name: "",
        department_name: "",
      });
    }
    setErrors({});
    setServerError("");
    setSuccessMessage("");
  }, [editData, open]);

  // ✅ React Query: Add User
  const { mutate: mutateAdd, isLoading: isAdding } = useMutation({
    mutationFn: addClientUserData,
    onSuccess: (data) => {
      setServerError("");
      setSuccessMessage(data?.message || "Client user added successfully!");
      if (onSuccess) onSuccess(data);
      setTimeout(() => {
        setSuccessMessage("");
        onClose();
      }, 1500);
      setForm({
        user_name: "",
        email: "",
        mobile_number: "",
        role_name: "",
        department_name: "",
      });
    },
    onError: (error) => {
      setSuccessMessage("");
      setServerError(error.message || "Something went wrong");
    },
  });

  // ✅ React Query: Update User
  const { mutate: mutateUpdate, isLoading: isUpdating } = useMutation({
    mutationFn: ({ user_id, payload }) =>
      updateClientUserData(user_id, payload),
    onSuccess: (data) => {
      setServerError("");
      setSuccessMessage("Client user updated successfully!");
      if (onSuccess) onSuccess(data);
      setTimeout(() => {
        setSuccessMessage("");
        onClose();
      }, 1500);
      setForm({
        user_name: "",
        email: "",
        mobile_number: "",
        role_name: "",
        department_name: "",
      });
    },
    onError: (error) => {
      setSuccessMessage("");
      setServerError(error.message || "Something went wrong");
    },
  });

  const isLoading = isAdding || isUpdating;

  // Auto-clear messages
  useEffect(() => {
    if (serverError) {
      const timer = setTimeout(() => setServerError(""), 3000);
      return () => clearTimeout(timer);
    }
  }, [serverError]);

  useEffect(() => {
    if (successMessage) {
      const timer = setTimeout(() => setSuccessMessage(""), 3000);
      return () => clearTimeout(timer);
    }
  }, [successMessage]);

  // Validation
  const validateField = (name, value) => {
    switch (name) {
      case "user_name":
        if (!value) return "User name is required";
        return "";
      case "email":
        if (!value) return "Email is required";
        if (!/\S+@\S+\.\S+/.test(value)) return "Invalid email format";
        return "";
      case "mobile_number":
        if (!value) return "Mobile number is required";
        if (!/^\d{10}$/.test(value)) return "Invalid mobile number";
        return "";
      case "role_name":
        if (!value) return "Role is required";
        return "";
      case "department_name":
        if (!value) return "Department is required";
        return "";
      default:
        return "";
    }
  };

  const validateAll = () => {
    const newErrors = {};
    Object.entries(form).forEach(([key, value]) => {
      const error = validateField(key, value);
      if (error) newErrors[key] = error;
    });
    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  // Handle input changes
  const handleChange = (e) => {
    const { name, value } = e.target;
    setForm((prev) => ({ ...prev, [name]: value }));
    setErrors((prev) => ({ ...prev, [name]: validateField(name, value) }));
    setServerError("");
    setSuccessMessage("");
  };

  // Handle submit
  const handleSubmit = (e) => {
    e.preventDefault();
    if (!validateAll()) return;

    const payload = {
      user_name: form.user_name.trim(),
      email: form.email.trim(),
      mobile_number: form.mobile_number.trim(),
      role_name: form.role_name.trim(),
      department_name: form.department_name.trim(),
    };

    if (editData) {
      mutateUpdate({ user_id: editData.user_id, payload });
    } else {
      mutateAdd(payload);
    }
  };

  return (
    <Dialog open={open} onClose={onClose} fullWidth maxWidth="sm">
      <DialogTitle>
        {editData ? "Edit Client User" : "Add Client User"}
      </DialogTitle>
      <DialogContent
        sx={{ display: "flex", flexDirection: "column", gap: 2, mt: 1 }}
      >
        {serverError && <Alert severity="error">{serverError}</Alert>}
        {successMessage && <Alert severity="success">{successMessage}</Alert>}

        <TextField
          className="!mt-4"
          label="User Name"
          name="user_name"
          value={form.user_name}
          onChange={handleChange}
          error={!!errors.user_name}
          helperText={errors.user_name}
          fullWidth
        />
        <TextField
          label="Email"
          name="email"
          value={form.email}
          onChange={handleChange}
          error={!!errors.email}
          helperText={errors.email}
          disabled={!!editData}
          fullWidth
        />
        <TextField
          label="Mobile Number"
          name="mobile_number"
          value={form.mobile_number}
          onChange={handleChange}
          error={!!errors.mobile_number}
          helperText={errors.mobile_number}
          fullWidth
        />
        <TextField
          select
          label="Role"
          name="role_name"
          value={form.role_name}
          onChange={handleChange}
          error={!!errors.role_name}
          helperText={errors.role_name}
          fullWidth
        >
          <MenuItem value="manager">Manager</MenuItem>
          <MenuItem value="employee">Employee</MenuItem>
        </TextField>

        <TextField
          label="Department"
          name="department_name"
          value={form.department_name}
          onChange={handleChange}
          error={!!errors.department_name}
          helperText={errors.department_name}
          fullWidth
        />
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose} disabled={isLoading}>
          Cancel
        </Button>
        <Button
          variant="contained"
          color="primary"
          onClick={handleSubmit}
          disabled={isLoading}
        >
          {isLoading ? (
            <CircularProgress size={24} />
          ) : editData ? (
            "Update"
          ) : (
            "Create"
          )}
        </Button>
      </DialogActions>
    </Dialog>
  );
};

export default AddClientUser;
