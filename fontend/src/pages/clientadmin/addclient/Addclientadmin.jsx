// import React, { useState, useEffect } from "react";
// import {
//   Dialog,
//   DialogTitle,
//   DialogContent,
//   DialogActions,
//   TextField,
//   Button,
//   Alert,
//   CircularProgress,
// } from "@mui/material";
// import { useMutation } from "@tanstack/react-query";
// import { addClientAdminData } from "../../../api/Clientadminapi";
// const Addclientadmin = ({ open, onClose, onSuccess }) => {
//   const [form, setForm] = useState({
//     user_name: "",
//     email: "",
//     mobile_number: "",
//     org_name: "",
//     org_email: "",
//   });

//   const [errors, setErrors] = useState({});
//   const [serverError, setServerError] = useState("");
//   const [successMessage, setSuccessMessage] = useState("");

//   // ✅ React Query mutation
//   const { mutate, isLoading } = useMutation({
//     mutationFn: addClientAdminData,
//     onSuccess: (data) => {
//       setServerError("");
//       const msg = data?.message || "Client Admin added successfully!";
//       setSuccessMessage(msg);

//       // Notify parent component
//       if (onSuccess) onSuccess(data);

//       // Auto-close dialog after 1.5s
//       setTimeout(() => {
//         setSuccessMessage("");
//         onClose();
//       }, 1500);

//       // Reset form
//       setForm({
//         user_name: "",
//         email: "",
//         mobile_number: "",
//         org_name: "",
//         org_email: "",
//       });
//     },
//     onError: (error) => {
//       setSuccessMessage("");
//       setServerError(error.message || "Something went wrong");
//     },
//   });

//   // Auto-clear messages
//   useEffect(() => {
//     if (serverError) {
//       const timer = setTimeout(() => setServerError(""), 3000);
//       return () => clearTimeout(timer);
//     }
//   }, [serverError]);

//   useEffect(() => {
//     if (successMessage) {
//       const timer = setTimeout(() => setSuccessMessage(""), 3000);
//       return () => clearTimeout(timer);
//     }
//   }, [successMessage]);

//   // ✅ Validation functions
//   const validateField = (name, value) => {
//     switch (name) {
//       case "user_name":
//         if (!value) return "User name is required";
//         return "";
//       case "email":
//         if (!value) return "Email is required";
//         if (!/\S+@\S+\.\S+/.test(value)) return "Invalid email format";
//         return "";
//       case "mobile_number":
//         if (!value) return "Mobile number is required";
//         if (!/^\d{10}$/.test(value)) return "Invalid mobile number";
//         return "";
//       case "org_name":
//         if (!value) return "Organization name is required";
//         return "";
//       case "org_email":
//         if (!value) return "Organization email is required";
//         if (!/\S+@\S+\.\S+/.test(value)) return "Invalid organization email";
//         return "";
//       default:
//         return "";
//     }
//   };

//   const validateAll = () => {
//     const newErrors = {};
//     Object.entries(form).forEach(([key, value]) => {
//       const error = validateField(key, value);
//       if (error) newErrors[key] = error;
//     });
//     setErrors(newErrors);
//     return Object.keys(newErrors).length === 0;
//   };

//   // ✅ Handle input changes
//   const handleChange = (e) => {
//     const { name, value } = e.target;
//     setForm((prev) => ({ ...prev, [name]: value }));
//     setErrors((prev) => ({ ...prev, [name]: validateField(name, value) }));
//     setServerError("");
//     setSuccessMessage("");
//   };

//   const handleSubmit = (e) => {
//     e.preventDefault();
//     if (!validateAll()) return;
//     mutate(form);
//   };

//   return (
//     <Dialog open={open} onClose={onClose} fullWidth maxWidth="sm">
//       <DialogTitle >Add Client Admin</DialogTitle>
//       <DialogContent sx={{ display: "flex", flexDirection: "column", gap: 2, mt: 1 }}>
//         {/* Server Error */}
//         {serverError && <Alert severity="error">{serverError}</Alert>}

//         {/* Success Message */}
//         {successMessage && <Alert severity="success">{successMessage}</Alert>}

//         {/* Form Fields */}
//         <TextField
//         className="!mt-4"
//           label="User Name"
//           name="user_name"
//           value={form.user_name}
//           onChange={handleChange}
//           error={!!errors.user_name}
//           helperText={errors.user_name}
//           fullWidth
//         />
//         <TextField
//           label="Email"
//           name="email"
//           value={form.email}
//           onChange={handleChange}
//           error={!!errors.email}
//           helperText={errors.email}
//           fullWidth
//         />
//         <TextField
//           label="Mobile Number"
//           name="mobile_number"
//           value={form.mobile_number}
//           onChange={handleChange}
//           error={!!errors.mobile_number}
//           helperText={errors.mobile_number}
//           fullWidth
//         />
//         <TextField
//           label="Organization Name"
//           name="org_name"
//           value={form.org_name}
//           onChange={handleChange}
//           error={!!errors.org_name}
//           helperText={errors.org_name}
//           fullWidth
//         />
//         <TextField
//           label="Organization Email"
//           name="org_email"
//           value={form.org_email}
//           onChange={handleChange}
//           error={!!errors.org_email}
//           helperText={errors.org_email}
//           fullWidth
//         />
//       </DialogContent>
//       <DialogActions>
//         <Button onClick={onClose} disabled={isLoading}>Cancel</Button>
//         <Button
//           variant="contained"
//           color="primary"
//           onClick={handleSubmit}
//           disabled={isLoading}
//         >
//           {isLoading ? <CircularProgress size={24} /> : "Create"}
//         </Button>
//       </DialogActions>
//     </Dialog>
//   );
// };

// export default Addclientadmin;


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
import { addClientAdminData, updateClientAdminData } from "../../../api/Clientadminapi";

const Addclientadmin = ({ open, onClose, onSuccess, editData }) => {
  const [form, setForm] = useState({
    user_name: "",
    email: "",
    mobile_number: "",
    org_name: "",
    org_email: "",
  });

  const [errors, setErrors] = useState({});
  const [serverError, setServerError] = useState("");
  const [successMessage, setSuccessMessage] = useState("");

  // Prefill form when editing
  useEffect(() => {
    if (editData) {
      setForm({
        user_name: editData.user_name || "",
        email: editData.email || "",
        mobile_number: editData.mobile_number || "",
        org_name: editData.org_name || "",
        org_email: editData.org_email || "",
      });
    } else {
      setForm({
        user_name: "",
        email: "",
        mobile_number: "",
        org_name: "",
        org_email: "",
      });
    }
    setErrors({});
    setServerError("");
    setSuccessMessage("");
  }, [editData, open]);

  // ✅ React Query: Add Mutation
  const { mutate: mutateAdd, isLoading: isAdding } = useMutation({
    mutationFn: addClientAdminData,
    onSuccess: (data) => {
      setServerError("");
      setSuccessMessage(data?.message || "Client Admin added successfully!");
      if (onSuccess) onSuccess(data);

      setTimeout(() => {
        setSuccessMessage("");
        onClose();
      }, 1500);

      setForm({
        user_name: "",
        email: "",
        mobile_number: "",
        org_name: "",
        org_email: "",
      });
    },
    onError: (error) => {
      setSuccessMessage("");
      setServerError(error.message || "Something went wrong");
    },
  });

  // ✅ React Query: Update Mutation
  const { mutate: mutateUpdate, isLoading: isUpdating } = useMutation({
     mutationFn: ({ user_id, payload }) => updateClientAdminData(user_id, payload),
    onSuccess: (data) => {
      setServerError("");
      setSuccessMessage("Client Admin updated successfully!");
      if (onSuccess) onSuccess(data);

      setTimeout(() => {
        setSuccessMessage("");
        onClose();
      }, 1500);

      // Reset form after update
      setForm({
        user_name: "",
        email: "",
        mobile_number: "",
        org_name: "",
        org_email: "",
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
      case "org_name":
        if (!value) return "Organization name is required";
        return "";
      case "org_email":
        if (!value) return "Organization email is required";
        if (!/\S+@\S+\.\S+/.test(value)) return "Invalid organization email";
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

    // Trim all fields before sending
    const payload = {
      user_name: form.user_name.trim(),
      email: form.email.trim(),
      mobile_number: form.mobile_number.trim(),
      org_name: form.org_name.trim(),
      org_email: form.org_email.trim(),
    };

    if (editData) {
    //   mutateUpdate({ ...payload, user_id: editData.user_id });
        mutateUpdate({ user_id: editData.user_id, payload });
    } else {
      mutateAdd(payload);
    }
  };

  return (
    <Dialog open={open} onClose={onClose} fullWidth maxWidth="sm">
      <DialogTitle>{editData ? "Edit Client Admin" : "Add Client Admin"}</DialogTitle>
      <DialogContent sx={{ display: "flex", flexDirection: "column", gap: 2, mt: 1 }}>
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
          label="Organization Name"
          name="org_name"
          value={form.org_name}
          onChange={handleChange}
          error={!!errors.org_name}
          helperText={errors.org_name}
          fullWidth
        />
        <TextField
          label="Organization Email"
          name="org_email"
          value={form.org_email}
          onChange={handleChange}
          error={!!errors.org_email}
          helperText={errors.org_email}
          disabled={!!editData}
          fullWidth
        />
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose} disabled={isLoading}>Cancel</Button>
        <Button
          variant="contained"
          color="primary"
          onClick={handleSubmit}
          disabled={isLoading}
        >
          {isLoading ? <CircularProgress size={24} /> : editData ? "Update" : "Create"}
        </Button>
      </DialogActions>
    </Dialog>
  );
};

export default Addclientadmin;
