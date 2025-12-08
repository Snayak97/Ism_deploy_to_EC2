

import React, { useEffect, useState } from "react";
import { Box, Button, CircularProgress, IconButton } from "@mui/material";
import { DataGrid } from "@mui/x-data-grid";
import EditIcon from "@mui/icons-material/Edit";
import DeleteIcon from "@mui/icons-material/Delete";
import { useClientsData } from "../../../hooks/useClientsData";
import { activateUser,deactivateUser } from "../../../api/Clientadminapi";
 import { deleteClientUserData } from "../../../api/ClientuserApi/ClientUserapi";

const ClientUserTable = ({ onEdit }) => {
  const { mutate, data, isPending, error } = useClientsData();
  const [selectedRows, setSelectedRows] = useState([]);

  useEffect(() => {
    mutate();
  }, [mutate]);

  if (isPending) return <CircularProgress />;
  if (error) return <div className="items-center text-center mt-5 text-red-500">Error: {error.message}</div>;
  if (!data?.users || data.users.length === 0) return <p className="items-center text-center mt-5 text-red-500">No ClientUsers Found</p>;

  const clientUsers = data.users;

  const formatDate = (date) => (date ? new Date(date).toLocaleString() : "-");

  const handleToggleStatus = async (row) => {
    try {
      if (row.is_active) {
        const res = await deactivateUser(row.user_id);
        alert(res.message);
      } else {
        const res = await activateUser(row.user_id);
        alert(res.message);
      }
      mutate();
    } catch (err) {
      alert(err.message);
    }
  };

  const handleDelete = async (row) => {
    if (!window.confirm("Are you sure you want to delete this client user?")) return;
    try {
      const res = await deleteClientUserData(row.user_id);
      alert(res.message);
      mutate();
    } catch (err) {
      alert(err.message);
    }
  };

//   const handleDeleteSelected = async () => {
//     if (!window.confirm(`Delete ${selectedRows.length} selected users?`)) return;
//     try {
//       for (let userId of selectedRows) {
//         await deleteNormalUser(userId);
//       }
//       alert("Selected users deleted successfully");
//       setSelectedRows([]);
//       mutate();
//     } catch (err) {
//       alert(err.message);
//     }
//   };

  const columns = [
    { field: "user_name", headerName: "User Name", flex: 1 },
    { field: "email", headerName: "Email", flex: 1 },
    { field: "department_name", headerName: "Department", flex: 1 },
    { field: "role_name", headerName: "Role", width: 120 },
    { field: "mobile_number", headerName: "Mobile", width: 140 },
    {
      field: "last_active_date",
      headerName: "Last Active",
      width: 180,
      renderCell: (params) => formatDate(params.row.last_active_date),
    },
    {
      field: "last_deactive_date",
      headerName: "Last Deactive",
      width: 180,
      renderCell: (params) => params.value || "No",
    },
  
    {
      field: "created_at",
      headerName: "Created Date",
      width: 180,
      renderCell: (params) => formatDate(params.row.created_at),
    },
    {
      field: "is_active",
      headerName: "Status",
      width: 150,
      renderCell: (params) => (
        <Button
          variant="contained"
          color={params.value ? "error" : "success"}
          size="small"
          onClick={() => handleToggleStatus(params.row)}
        >
          {params.value ? "Deactivate" : "Activate"}
        </Button>
      ),
    },
    {
      field: "actions",
      headerName: "Actions",
      width: 130,
      sortable: false,
      renderCell: (params) => (
        <>
          <IconButton onClick={() => {onEdit(params.row)}}>
            <EditIcon color="primary" />
          </IconButton>
          <IconButton onClick={() => handleDelete(params.row)}>
            <DeleteIcon color="error" />
          </IconButton>
        </>
      ),
    },
  ];

  return (
    <Box className="w-full mt-5">
      {/* DELETE BUTTON OUTSIDE TABLE */}
      <Box className="mb-3 flex justify-end">
        {selectedRows.length > 0 && (
          <Button
            variant="contained"
            color="error"
            onClick={handleDeleteSelected}
          >
            Delete Selected ({selectedRows.length})
          </Button>
        )}
      </Box>

      <DataGrid
        rows={clientUsers}
        columns={columns}
        getRowId={(row) => row.user_id}
        pageSize={5}
        rowsPerPageOptions={[5, 10]}
        autoHeight
        checkboxSelection
        selectionModel={selectedRows}
        onSelectionModelChange={(newSelection) => {
        
          const ids = Array.isArray(newSelection) ? newSelection : [...newSelection];
          setSelectedRows(ids);
        }}
      />
    </Box>
  );
};

export default ClientUserTable;
