import React, { useEffect, useState } from "react";
import axios from "axios";
import {
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Paper,
  Typography,
  CircularProgress,
  Box,
  Button,
  Stack,
} from "@mui/material";

const ShippingLocationsMaster = () => {
  const [locations, setLocations] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    axios
      .get("http://127.0.0.1:5000/api/v1/shippinglocationmaster/get_shiipinglocation_masters")
      .then((res) => {
        const data = res.data.shiiping_location_master || [];
        setLocations(data);
        setLoading(false);
      })
      .catch((err) => {
        console.error("API Error:", err);
        setError("Failed to load shipping locations.");
        setLoading(false);
      });
  }, []);

  const columns = [
    { label: "Name", key: "shippinglocation_name" },
    { label: "Code", key: "shippinglocation_code" },
    { label: "Address", key: "address" },
    { label: "City", key: "city" },
    { label: "Country", key: "country" },
    { label: "Pincode", key: "pincode" },
    { label: "Contact Person", key: "contact_person" },
    { label: "Contact Number", key: "contact_number" },
    { label: "Is Active", key: "is_active" },
  ];

  const handleEdit = (location) => {
    alert(`Edit shipping location: ${location.shippinglocation_name}`);
  };

  const handleDelete = (id) => {
    if (
      window.confirm("Are you sure you want to delete this shipping location?")
    ) {
      alert(`Deleted shipping location with id: ${id}`);
      setLocations((prev) => prev.filter((loc) => loc.shippinglocation_id !== id));
    }
  };

  if (loading) {
    return (
      <Box display="flex" justifyContent="center" alignItems="center" minHeight="300px">
        <CircularProgress />
      </Box>
    );
  }

  if (error) {
    return (
      <Typography variant="body1" color="error" align="center" sx={{ mt: 4 }}>
        {error}
      </Typography>
    );
  }

  if (!locations.length) {
    return (
      <Typography variant="body1" align="center" sx={{ mt: 4 }}>
        No shipping locations available.
      </Typography>
    );
  }

  return (
    <div className="p-4" style={{ overflowX: "auto", width: "100%" }}>
      <Typography variant="h5" gutterBottom>
        Shipping Locations
      </Typography>

      <TableContainer component={Paper} sx={{ minWidth: 800 }}>
        <Table size="small" stickyHeader sx={{ minWidth: 800 }}>
          <TableHead>
            <TableRow>
              {columns.map((col, idx) => (
                <TableCell key={idx}>
                  <strong>{col.label}</strong>
                </TableCell>
              ))}
              <TableCell>
                <strong>Action</strong>
              </TableCell>
            </TableRow>
          </TableHead>

          <TableBody>
            {locations.map((row, rowIdx) => (
              <TableRow key={rowIdx}>
                {columns.map((col, idx) => {
                  let value = row[col.key];
                  if (typeof value === "boolean") value = value ? "Yes" : "No";
                  if (value === null || value === undefined) value = "-";
                  return <TableCell key={idx}>{value}</TableCell>;
                })}
                <TableCell>
                  <Stack direction="row" spacing={1}>
                    <Button
                      variant="contained"
                      size="small"
                      color="primary"
                      onClick={() => handleEdit(row)}
                      sx={{ backgroundColor: "#1976d2", "&:hover": { backgroundColor: "#115293" } }}
                    >
                      Edit
                    </Button>
                    <Button
                      variant="contained"
                      size="small"
                      color="error"
                      onClick={() => handleDelete(row.shippinglocation_id)}
                      sx={{ backgroundColor: "#d32f2f", "&:hover": { backgroundColor: "#9a0007" } }}
                    >
                      Delete
                    </Button>
                  </Stack>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </TableContainer>
    </div>
  );
};

export default ShippingLocationsMaster;
