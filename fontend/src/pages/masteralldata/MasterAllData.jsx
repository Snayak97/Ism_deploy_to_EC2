import React, { useState, useEffect, useMemo } from "react";
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
  Stack,
  Button,
} from "@mui/material";

const excludedKeys = ["created_at", "updated_at"];
const isExcluded = (key) =>
  excludedKeys.includes(key.toLowerCase()) || key.toLowerCase().endsWith("_id");

const apiConfig = [
  {
    label: "Marketplace Master",
    url: "http://127.0.0.1:5000/api/v1/marketplacemaster/get_marketplace_masters",
  },
  {
    label: "Platform Master",
    url: "http://127.0.0.1:5000/api/v1/platformmaster/get_platform_masters",
  },
  // Add more APIs here if needed
];

const MasterAllData = () => {
  const [activeIndex, setActiveIndex] = useState(0);
  const [data, setData] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const extractDataArray = (obj) => {
    if (!obj) return [];
    for (const key in obj) {
      if (Array.isArray(obj[key])) return obj[key];
    }
    return [];
  };

  const fetchData = async (url) => {
    setLoading(true);
    setError(null);
    try {
      const res = await axios.get(url);
      const arr = extractDataArray(res.data);
      setData(arr);
    } catch (err) {
      if (err.response && err.response.data) {
        let msg = "";
        if (typeof err.response.data === "string") msg = err.response.data;
        else if (err.response.data.error) msg = err.response.data.error;
        else if (err.response.data.message) msg = err.response.data.message;
        else msg = JSON.stringify(err.response.data);
        setError(`Error ${err.response.status}: ${msg}`);
      } else {
        setError("Network or unknown error");
      }
      setData([]);
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData(apiConfig[activeIndex].url);
  }, [activeIndex]);

  const columns = useMemo(() => {
    if (!data.length) return [];
    // Build columns list for the table - keys & labels
    return Object.keys(data[0])
      .filter((key) => !isExcluded(key))
      .map((key) => ({ key, label: key.replace(/_/g, " ") }));
  }, [data]);

  // Stub handlers for edit and delete, implement as needed
  const handleEdit = (row) => {
    alert("Edit clicked for: " + JSON.stringify(row));
  };

  const handleDelete = (id) => {
    alert("Delete clicked for ID: " + id);
  };

  return (
    <div className="min-h-screen bg-gray-50 p-4 dark:bg-neutral-900 dark:text-white">
      {/* Single line: Select left, title centered */}
      <div
        className="flex items-center mb-4"
        style={{ justifyContent: "space-between" }}
      >
        {/* Select dropdown aligned left */}
        <select
          value={activeIndex}
          onChange={(e) => setActiveIndex(Number(e.target.value))}
          className="border dark:bg-neutral-900 dark:text-white bg-white border-gray-300 rounded-md px-4 py-2 text-base
            focus:outline-none  focus:ring-blue-500 transition "
          style={{ minWidth: 200 }}
        >
          {apiConfig.map((api, idx) => (
            <option key={api.label} value={idx}>
              {api.label}
            </option>
          ))}
        </select>

        {/* Table name centered */}
        <Typography
          variant="h5"
          sx={{ fontWeight: "bold", flexGrow: 1, textAlign: "center" }}
          component="div"
        >
          {apiConfig[activeIndex].label.replace(/_/g, " ")}
        </Typography>

        {/* Invisible div to keep space on right for center alignment */}
        <div style={{ width: 200 }}></div>
      </div>

      {/* Loading & Error */}
      {loading && (
        <Typography
          variant="body1"
          color="text.secondary"
          align="center"
          sx={{ mt: 4 }}
        >
          Loading...
        </Typography>
      )}
      {error && (
        <Typography
          variant="body1"
          color="error"
          align="center"
          sx={{ mt: 4, fontWeight: "bold" }}
        >
          {error}
        </Typography>
      )}

      {/* Table */}
      {!loading && !error && data.length > 0 ? (
        <div
          className="p-4"
          style={{
            width: "100%",
            overflowX: "auto",
          }}
        >
          <TableContainer
            component={Paper}
            sx={{
              minWidth: 650,
            }}
          >
            <Table size="small" stickyHeader sx={{ minWidth: 650 }}>
              <TableHead>
                <TableRow>
                  {columns.map((col, idx) => (
                    <TableCell key={idx}>
                      <strong>{col.label}</strong>
                    </TableCell>
                  ))}
                  {/* <TableCell>
                    <strong>Action</strong>
                  </TableCell> */}
                </TableRow>
              </TableHead>

              <TableBody>
                {data.map((row, rowIdx) => (
                  <TableRow key={rowIdx} hover>
                    {columns.map((col, idx) => {
                      let value = row[col.key];
                      if (typeof value === "boolean")
                        value = value ? "Yes" : "No";
                      if (value === null || value === undefined) value = "-";
                      return <TableCell key={idx}>{value}</TableCell>;
                    })}
                    {/* <TableCell>
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
                          onClick={() =>
                            handleDelete(
                              row[
                                Object.keys(row).find((k) =>
                                  k.toLowerCase().endsWith("_id")
                                )
                              ]
                            )
                          }
                          sx={{
                            backgroundColor: "#d32f2f",
                            "&:hover": { backgroundColor: "#9a0007" },
                          }}
                        >
                          Delete
                        </Button>
                      </Stack>
                    </TableCell> */}
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>
        </div>
      ) : (
        !loading &&
        !error && (
          <Typography
            variant="body1"
            color="text.secondary"
            align="center"
            sx={{ mt: 4 }}
          >
            No data available
          </Typography>
        )
      )}
    </div>
  );
};

export default MasterAllData;
