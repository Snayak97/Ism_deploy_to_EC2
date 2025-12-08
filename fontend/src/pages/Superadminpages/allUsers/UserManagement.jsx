import React, { useEffect, useState } from "react";
import {
  Box,
  Button,
  CircularProgress,
  Tab,
  Tabs,
  Typography,
  TextField,
  MenuItem,
  InputAdornment,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  TextareaAutosize,
  IconButton,
} from "@mui/material";
import { DataGrid } from "@mui/x-data-grid";
import Axios from "../../../api/Axios";
import { IoSearch } from "react-icons/io5";
import EditIcon from "@mui/icons-material/Edit";
import DeleteIcon from "@mui/icons-material/Delete";

import Addclientadmin from "../../clientadmin/addclient/Addclientadmin";
import { deleteNormalUser } from "../../../services/AuthServices";
import {
  deleteClientAdminData,
  activateUser, 
  deactivateUser, 
} from "../../../api/Clientadminapi";

const UserManagement = () => {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState(0);
  const [selectedClient, setSelectedClient] = useState("");
  const [searchTerm, setSearchTerm] = useState("");
  const [openAddUser, setOpenAddUser] = useState(false);
  const [editClientData, setEditClientData] = useState(null);

  useEffect(() => {
    fetchData();
  }, []);

  const fetchData = async () => {
    try {
      const res = await Axios.get("/auth/all_clientsadmin_and_normal_users");
      setData(res.data.data);
    } catch (error) {
      console.error("Error fetching data:", error);
    } finally {
      setLoading(false);
    }
  };

  const handleTabChange = (e, newValue) => setActiveTab(newValue);
  const handleClientChange = (e) => setSelectedClient(e.target.value);
  const handleSearchChange = (e) => setSearchTerm(e.target.value);

  const handleToggleStatus = async (row) => {
  try {
    if (row.is_active) {
      // Deactivate
      const data = await deactivateUser(row.user_id);
      alert(data.message);
    } else {
      // Activate
      const data = await activateUser(row.user_id);
      alert(data.message);
    }


    fetchData();
  } catch (err) {
    alert(err.message);
  }
};

  

  const handleEdit = (row) => {
    setEditClientData(row);
    setOpenAddUser(true);
  };

  const handleDelete = async (user_id) => {
    if (!window.confirm("Are you sure you want to delete this Client Admin?"))
      return;

    try {
      const data = await deleteClientAdminData(user_id);
      alert(data.message);

      // Refresh the table or remove deleted item from state
      fetchData();
    } catch (err) {
      alert(err.message);
    }
  };

  const handleDeleteNormalUser = async (user_id) => {
  if (!window.confirm("Are you sure you want to delete this Normal User?")) return;

  try {
    const data = await deleteNormalUser(user_id);
    alert(data.message);
    fetchData(); // refresh table
  } catch (err) {
    alert(err.message);
  }
};

  

  if (loading) return <CircularProgress />;
  if (!data) return <p>No data found</p>;

  // Filter clients for dropdown
  const filteredClients =
    searchTerm === ""
      ? data.clients
      : data.clients.filter((c) =>
          c.org_name.toLowerCase().includes(searchTerm.toLowerCase())
        );

  // ✅ Normal Users Columns
  const normalUserColumns = [
    { field: "user_name", headerName: "User Name", flex: 1 },
    { field: "email", headerName: "Email", flex: 1 },
    { field: "role_name", headerName: "Role", width: 120 },
    { field: "mobile_number", headerName: "Mobile", width: 140 },
     {
    field: "is_verified",
    headerName: "Verified",
    width: 120,
    renderCell: (params) => (params.value ? "Yes" : "No"),
  },
  {
    field: "last_active_date",
    headerName: "Last Active",
    width: 180,
    renderCell: (params) => params.value || "No",
  },
  {
    field: "last_deactive_date",
    headerName: "Last Deactive",
    width: 180,
    renderCell: (params) => params.value || "No",
  },
  { field: "created_at", headerName: "Created Date", width: 180 },
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
          {/* <IconButton onClick={() => handleEdit(params.row)}>
            <EditIcon color="primary" />
          </IconButton> */}
          <IconButton onClick={() => handleDeleteNormalUser(params.row)}>
            <DeleteIcon color="error" />
          </IconButton>
        </>
      ),
    },
  ];

  // ✅ Client Admins Columns
  const clientColumns = [
    { field: "org_name", headerName: "Org Name", flex: 1 },
    { field: "org_email", headerName: "Org Email", flex: 1 },
    { field: "user_name", headerName: "User Name", flex: 1 },
    { field: "email", headerName: "Email", flex: 1 },
    { field: "role_name", headerName: "Role", width: 120 },
    { field: "mobile_number", headerName: "Mobile", width: 140 },
    { field: "last_active_date", headerName: "Last Active", width: 180 },
    {
  field: "last_deactive_date",
  headerName: "Last Deactive",
  width: 180,
  renderCell: (params) => params.value ? params.value : "No"
},
    { field: "created_at", headerName: "Created Date", width: 180 },
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
          <IconButton onClick={() => handleEdit(params.row)}>
            <EditIcon color="primary" />
          </IconButton>
          <IconButton onClick={() => handleDelete(params.row.user_id)}>
            <DeleteIcon color="error" />
          </IconButton>
        </>
      ),
    },
  ];

  const getClientUsers = () =>
    selectedClient
      ? data.clients
          .find((c) => c.client_id === selectedClient)
          ?.client_admins.map((admin) => ({
            ...admin,
            org_name:
              data.clients.find((c) => c.client_id === selectedClient)
                ?.org_name || "",
            org_email:
              data.clients.find((c) => c.client_id === selectedClient)
                ?.org_email || "",
          })) || []
      : [];

  return (
    <div className="w-[90%]">
      <Box sx={{ p: 3 }} className="">
        {/* Tabs + Add Client Button */}
        <Box
          sx={{
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
            mb: 2,
          }}
        >
          <Tabs
            value={activeTab}
            className="!dark:bg-neutral-900 !dark:text-white !dark:shadow-white"
            onChange={handleTabChange}
            textColor="primary"
            indicatorColor="primary"
          >
            <Tab label="Normal Users" className="dark:bg-neutral-900 dark:shadow-white" />
            <Tab label="Clients" className="d!ark:bg-neutral-900 !dark:shadow-white !dark:text-white" />
          </Tabs>
           <Box sx={{ display: "flex", gap: 2 }}>
    {/* New button left of Add Client */}
    {/* <Button
      variant="contained"
      color="primary"
      onClick={() => alert("New Button Clicked")}
    >
      Add User
    </Button> */}

    <Button
      variant="contained"
      color="primary"
      onClick={() => {
        setEditClientData(null);
        setOpenAddUser(true);
      }}
    >
      Add Client
    </Button>
  </Box>


          {/* <Button
            variant="contained"
            color="primary"
            onClick={() => {
              setEditClientData(null);
              setOpenAddUser(true);
            }}
          >
            Add Client
          </Button> */}
        </Box>

        {/* Normal Users Table */}
        {activeTab === 0 && (
          <Box sx={{ width: "100%", overflowX: "auto" }}>
            <DataGrid
              rows={data.normal_users}
              columns={normalUserColumns}
              getRowId={(row) => row.user_id}
              pageSize={5}
              rowsPerPageOptions={[5, 10]}
              autoHeight
              checkboxSelection
              sx={{ minWidth: 900 }}
            />
          </Box>
        )}

        {/* Clients Tab */}
        {activeTab === 1 && (
          <Box >
            {/* Search + Client Select */}
            <Box sx={{ display: "flex", gap: 2, flexWrap: "wrap", mb: 2 }}>
              <TextField
               className=" dark:!text-gray-500 dark:!placeholder-gray-500 !bg-white  rounded-md dark:!shadow-md"
                placeholder="Search clients..."
                value={searchTerm}
                onChange={handleSearchChange}
                size="small"
                variant="outlined"
                sx={{ minWidth: 200 }}
                InputProps={{
                   className: " dark:!placeholder-gray-500",
                  endAdornment: (
                    <InputAdornment position="end">
                      <IoSearch size={20} />
                    </InputAdornment>
                  ),
                }}
              />

              <TextField
                
                select
                
                label="Select Client"
                value={selectedClient}
                onChange={handleClientChange}
                size="small"
                variant="outlined"
                sx={{ minWidth: 200 }}
                className=" dark:!text-white  dark:!placeholder-gray-100 !rounded-md !bg-white"
              >
                {filteredClients.map((client) => (
                  <MenuItem className= "!dark:bg-neutral-900 !dark:text-white" key={client.client_id} value={client.client_id}>
                    {client.org_name}
                  </MenuItem>
                ))}
              </TextField>
            </Box>

            {/* Client Users Table */}
            {selectedClient && (
              <Box sx={{ width: "100%", overflowX: "auto" }}>
                <DataGrid
                  rows={getClientUsers()}
                  columns={clientColumns}
                  getRowId={(row) => row.user_id}
                  pageSize={5}
                  rowsPerPageOptions={[5, 10]}
                  autoHeight
                  checkboxSelection
                  sx={{ minWidth: 1200 }}
                />
              </Box>
            )}
          </Box>
        )}

        {/* Add Client Dialog */}
        <Addclientadmin
          className=""
          open={openAddUser}
          onClose={() => {
            setOpenAddUser(false);
            setEditClientData(null); // reset edit data
          }}
          onSuccess={() => fetchData()} // refresh data after add
          editData={editClientData} // if editing
        />
      </Box>
    </div>
  );
};

export default UserManagement;

// import React, { useEffect, useState } from "react";
// import {
//   Box,
//   Button,
//   CircularProgress,
//   Tab,
//   Tabs,
//   Typography,
//   TextField,
//   MenuItem,
//   InputAdornment,
//   Dialog,
//   DialogTitle,
//   DialogContent,
//   DialogActions,
//   TextareaAutosize,
// } from "@mui/material";
// import { DataGrid } from "@mui/x-data-grid";
// import Axios from "../../../api/Axios";
// import { IoSearch } from "react-icons/io5";

// const UserManagement = () => {
//   const [data, setData] = useState(null);
//   const [loading, setLoading] = useState(true);
//   const [activeTab, setActiveTab] = useState(0);
//   const [selectedClient, setSelectedClient] = useState("");
//   const [searchTerm, setSearchTerm] = useState("");

//   const [openAddUser, setOpenAddUser] = useState(false);

//   useEffect(() => {
//     fetchData();
//   }, []);

//   const fetchData = async () => {
//     try {
//       const res = await Axios.get("/auth/all_clientsadmin_and_normal_users");
//       setData(res.data.data);
//     } catch (error) {
//       console.error("Error fetching data:", error);
//     } finally {
//       setLoading(false);
//     }
//   };

//   const handleTabChange = (e, newValue) => setActiveTab(newValue);
//   const handleClientChange = (e) => setSelectedClient(e.target.value);
//   const handleSearchChange = (e) => setSearchTerm(e.target.value);

//   if (loading) return <CircularProgress />;
//   if (!data) return <p>No data found</p>;

//   // Filter clients for select dropdown
//   const filteredClients =
//     searchTerm === ""
//       ? data.clients
//       : data.clients.filter((c) =>
//           c.org_name.toLowerCase().includes(searchTerm.toLowerCase())
//         );

//   const columns = [
//     { field: "user_name", headerName: "Name", flex: 1, filterable: true },
//     { field: "email", headerName: "Email", flex: 1, filterable: true },
//     { field: "role_name", headerName: "Role", width: 130, filterable: true },
//     {
//       field: "department_name",
//       headerName: "Department",
//       width: 150,
//       filterable: true,
//     },
//     {
//       field: "is_active",
//       headerName: "Status",
//       width: 130,
//       filterable: false,
//       renderCell: (params) => (
//         <Button
//           variant="contained"
//           color={params.value ? "error" : "success"}
//           size="small"
//           onClick={() =>
//             alert(
//               `${params.row.user_name} is now ${
//                 params.value ? "Deactivated" : "Activated"
//               }`
//             )
//           }
//         >
//           {params.value ? "Deactivate" : "Activate"}
//         </Button>
//       ),
//     },
//   ];

//   const getClientUsers = () =>
//     selectedClient
//       ? data.clients.find((c) => c.client_id === selectedClient).client_admins
//       : [];

//   return (
//     <Box sx={{ p: 3 }}>
//       {/* Tabs + Add User Button */}
//       <Box
//         sx={{
//           display: "flex",
//           justifyContent: "space-between",
//           alignItems: "center",
//           mb: 2,
//         }}
//       >
//         <Tabs
//           value={activeTab}
//           onChange={handleTabChange}
//           textColor="primary"
//           indicatorColor="primary"
//         >
//           <Tab label="Normal Users" />
//           <Tab label="Clients" />
//         </Tabs>

//         <Button
//           variant="contained"
//           color="primary"
//           onClick={() => setOpenAddUser(true)}
//         >
//           Add Client
//         </Button>
//       </Box>

//       {/* Normal Users Table */}
//       {activeTab === 0 && (
//         <Box sx={{ width: "100%", overflowX: "auto" }}>
//           <DataGrid
//             rows={data.normal_users}
//             columns={columns}
//             getRowId={(row) => row.user_id}
//             pageSize={5}
//             rowsPerPageOptions={[5, 10]}
//             autoHeight
//             checkboxSelection
//             disableColumnResize={false} // allow column resize
//             columnBuffer={columns.length} // buffer for horizontal scroll
//             sx={{
//               minWidth: 800, // force horizontal scroll if columns exceed
//             }}
//           />
//         </Box>
//       )}

//       {/* Clients Tab */}
//       {activeTab === 1 && (
//         <Box>
//           {/* Search + Client Select */}
//           <Box sx={{ display: "flex", gap: 2, flexWrap: "wrap", mb: 2 }}>
//             <TextField
//               className=" !bg-white !text-transparent !text-3xl "
//               placeholder="Search clients..."
//               value={searchTerm}
//               onChange={handleSearchChange}
//               size="small"
//               variant="outlined"
//               sx={{ minWidth: 200 }}
//               InputProps={{
//                 endAdornment: (
//                   <InputAdornment position="end">
//                     <IoSearch size={20} />
//                   </InputAdornment>
//                 ),
//               }}
//             />

//             <TextField
//               select
//               label="Select Client"
//               value={selectedClient}
//               onChange={handleClientChange}
//               size="small"
//               variant="outlined"
//               sx={{ minWidth: 200 }}
//             >
//               {filteredClients.map((client) => (
//                 <MenuItem key={client.client_id} value={client.client_id}>
//                   {client.org_name}
//                 </MenuItem>
//               ))}
//             </TextField>
//           </Box>

//           {/* Client Users Table */}
//           {selectedClient && (
//             <Box sx={{ width: "100%", overflowX: "auto" }}>
//               <DataGrid
//                 rows={getClientUsers()}
//                 columns={columns}
//                 getRowId={(row) => row.user_id}
//                 pageSize={5}
//                 rowsPerPageOptions={[5, 10]}
//                 autoHeight
//                 checkboxSelection
//               />
//             </Box>
//           )}
//         </Box>
//       )}

//       <Dialog
//         open={openAddUser}
//         onClose={() => setOpenAddUser(false)}
//         fullWidth
//       >
//         <DialogTitle>Add Client</DialogTitle>
//         <DialogContent
//           sx={{ display: "flex", flexDirection: "column", gap: 2 }}
//         >
//           <TextField label="Name" fullWidth />
//           <TextField label="Email" fullWidth />
//           <TextField label="Department" fullWidth />
//           <TextField label="Role" fullWidth />
//           <TextField label="Mobile Number" fullWidth />
//           <TextareaAutosize
//             minRows={3}
//             placeholder="Notes / Remarks"
//             className="!border !border-gray-300 !border-solid !rounded-md p-2"
//           />
//         </DialogContent>
//         <DialogActions>
//           <Button onClick={() => setOpenAddUser(false)}>Cancel</Button>
//           <Button variant="contained" color="primary">
//             Create
//           </Button>
//         </DialogActions>
//       </Dialog>
//     </Box>
//   );
// };

// export default UserManagement;
