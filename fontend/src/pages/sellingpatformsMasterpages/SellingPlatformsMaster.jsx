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

const SellingPlatformsMaster = () => {
  const [platforms, setPlatforms] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    axios
      .get("http://127.0.0.1:5000/api/v1/sellingplatformmaster/get_sellingplatform_masters")
      .then((res) => {
        const data = res.data.selling_platform_masters || [];
        setPlatforms(data);
        setLoading(false);
      })
      .catch((err) => {
        console.error("API Error:", err);
        setError("Failed to load selling platforms.");
        setLoading(false);
      });
  }, []);

  const columns = [
    { label: "Platform Name", key: "selling_platform_name" },
    { label: "Country", key: "country" },
    { label: "Currency", key: "currency" },
    { label: "Type", key: "selling_platform_type" },
    { label: "API Enabled", key: "api_enabled" },
    { label: "Is Active", key: "is_active" },
    { label: "URL", key: "sales_channel_url" },
  ];

  const handleEdit = (platform) => {
    alert(`Edit platform: ${platform.selling_platform_name}`);
  };

  const handleDelete = (id) => {
    if (window.confirm("Are you sure you want to delete this selling platform?")) {
      alert(`Deleted platform with id: ${id}`);
      setPlatforms((prev) => prev.filter((p) => p.selling_platform_id !== id));
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

  if (!platforms.length) {
    return (
      <Typography variant="body1" align="center" sx={{ mt: 4 }}>
        No selling platforms data available.
      </Typography>
    );
  }

  return (
    <div className="p-4" style={{ overflowX: "auto", width: "100%" }}>
      <Typography variant="h5" gutterBottom>
        Selling Platforms
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
            {platforms.map((row, rowIdx) => (
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
                      onClick={() => handleDelete(row.selling_platform_id)}
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

export default SellingPlatformsMaster;
