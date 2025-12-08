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

const MarketplaceMaster = () => {
  const [marketplaces, setMarketplaces] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    axios
      .get("http://127.0.0.1:5000/api/v1/marketplacemaster/get_marketplace_masters")
      .then((res) => {
        const data = res.data.marketplace_masters || [];
        setMarketplaces(data);
        setLoading(false);
      })
      .catch((err) => {
        console.error("API Error:", err);
        setError("Failed to load data from API.");
        setLoading(false);
      });
  }, []);

  const columns = [
    { label: "Marketplace Name", key: "marketplace_name" },
    { label: "Country", key: "country" },
    { label: "Currency", key: "currency" },
    { label: "Code", key: "marketplace_code" },
    { label: "API Enabled", key: "api_enabled" },
    { label: "Is Active", key: "is_active" },
    { label: "Shipping Location", key: "shipping_location" },
    { label: "Website URL", key: "website_url" },
  ];

  const handleEdit = (marketplace) => {
    alert(`Edit marketplace: ${marketplace.marketplace_name}`);
  };

  const handleDelete = (marketplaceId) => {
    if (
      window.confirm(
        "Are you sure you want to delete this marketplace? This action cannot be undone."
      )
    ) {
      alert(`Deleted marketplace with id: ${marketplaceId}`);
      setMarketplaces((prev) =>
        prev.filter((m) => m.marketplace_id !== marketplaceId)
      );
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

  if (!marketplaces.length) {
    return (
      <Typography variant="body1" align="center" sx={{ mt: 4 }}>
        No marketplaces data available.
      </Typography>
    );
  }

  return (
    <div
      className="p-4"
      style={{
        width: "100%",
        overflowX: "auto", // allow horizontal scrolling if needed
      }}
    >
      <Typography variant="h5" gutterBottom>
        Marketplaces
      </Typography>

      <TableContainer
        component={Paper}
        sx={{
          minWidth: 650, // make table minimum width so columns don't shrink too much
          // maxWidth: "100%",  // Optional: can restrict max width to container width
        }}
      >
        <Table
          size="small"
          stickyHeader
          sx={{
            minWidth: 650, // ensure table width doesn't collapse
          }}
        >
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
            {marketplaces.map((row, rowIdx) => (
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
                      sx={{
                        backgroundColor: "#1976d2",
                        "&:hover": { backgroundColor: "#115293" },
                      }}
                    >
                      Edit
                    </Button>
                    <Button
                      variant="contained"
                      size="small"
                      color="error"
                      onClick={() => handleDelete(row.marketplace_id)}
                      sx={{
                        backgroundColor: "#d32f2f",
                        "&:hover": { backgroundColor: "#9a0007" },
                      }}
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

export default MarketplaceMaster;
