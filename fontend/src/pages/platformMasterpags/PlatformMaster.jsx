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

const PlatformMaster = () => {
  const [platforms, setPlatforms] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    axios
      .get("http://127.0.0.1:5000/api/v1/platformmaster/get_platform_masters")
      .then((res) => {
        const data = res.data.platform_master || [];
        setPlatforms(data);
        setLoading(false);
      })
      .catch((err) => {
        console.error("API Error:", err);
        setError("Failed to load platform masters.");
        setLoading(false);
      });
  }, []);

  const columns = [
    { label: "Platform Name", key: "platform_name" },
    { label: "Address", key: "address" },
    { label: "Description", key: "description" },
    { label: "Email", key: "email" },
  ];

  const handleEdit = (platform) => {
    alert(`Edit platform: ${platform.platform_name}`);
  };

  const handleDelete = (platformId) => {
    if (window.confirm("Are you sure you want to delete this platform?")) {
      alert(`Deleted platform with id: ${platformId}`);
      setPlatforms((prev) => prev.filter((p) => p.platform_id !== platformId));
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
        No platform data available.
      </Typography>
    );
  }

  return (
    <div className="p-4" style={{ overflowX: "auto", width: "100%" }}>
      <Typography variant="h5" gutterBottom>
        Platform Masters
      </Typography>

      <TableContainer component={Paper} sx={{ minWidth: 800 }}>
        <Table size="small" stickyHeader>
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
            {platforms.map((row, idx) => (
              <TableRow key={idx}>
                {columns.map((col, cidx) => {
                  let value = row[col.key];
                  if (!value) value = "-";
                  return <TableCell key={cidx}>{value}</TableCell>;
                })}
                <TableCell>
                  <Stack direction="row" spacing={1}>
                    <Button
                      variant="contained"
                      size="small"
                      color="primary"
                      onClick={() => handleEdit(row)}
                    >
                      Edit
                    </Button>
                    <Button
                      variant="contained"
                      size="small"
                      color="error"
                      onClick={() => handleDelete(row.platform_id)}
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

export default PlatformMaster;
