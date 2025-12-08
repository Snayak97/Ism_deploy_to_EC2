import React, { useState, useMemo } from "react";
import {
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Paper,
  Typography,
  Select,
  MenuItem,
  FormControl,
  InputLabel,
} from "@mui/material";

const excludedKeys = ["created_at", "updated_at"];
const isExcluded = (key) =>
  excludedKeys.includes(key.toLowerCase()) || key.toLowerCase().endsWith("_id");

const AllDataTables = ({ data }) => {
  const sections = useMemo(() => {
    if (!data) return [];
    return Object.entries(data).filter(
      ([, sectionObj]) =>
        sectionObj?.valid_data &&
        Array.isArray(sectionObj.valid_data) &&
        sectionObj.valid_data.length > 0
    );
  }, [data]);

  const [selectedIndex, setSelectedIndex] = useState(0);

  if (!sections.length) {
    return (
      <Typography
        variant="body1"
        color="text.secondary"
        align="center"
        sx={{ mt: 4 }}
      >
        No data available
      </Typography>
    );
  }

  const [sectionKey, sectionObj] = sections[selectedIndex];
  const rows = sectionObj.valid_data;
  const columns = Object.keys(rows[0] || {}).filter((key) => !isExcluded(key));

  return (
    <div className="min-h-screen bg-gray-50 p-4">
      {/* Flex container for select and title */}
      <div className="flex items-center justify-between mb-4">
        {/* Select box left aligned */}
        <div className="min-w-[250px] bg-white  focus:ring-blue-500">
          <FormControl fullWidth>
            <InputLabel id="section-select-label">Select Section</InputLabel>
            <Select
              labelId="section-select-label"
              value={selectedIndex}
              label="Select Section"
              onChange={(e) => setSelectedIndex(e.target.value)}
            >
              {sections.map(([key], idx) => (
                <MenuItem key={key} value={idx}>
                  {key.replace(/_/g, " ").toUpperCase()}
                </MenuItem>
              ))}
            </Select>
          </FormControl>
        </div>

        {/* Table name centered */}
        <Typography
          variant="h5"
          component="div"
          className="font-bold flex-grow text-center"
        >
          {sectionKey.replace(/_/g, " ").toUpperCase()}
        </Typography>

        {/* Placeholder to balance flex space */}
        <div className="min-w-[250px]" />
      </div>

      {/* Table */}
      <TableContainer component={Paper} sx={{ minWidth: 650 }}>
        <Table size="small" stickyHeader sx={{ minWidth: 650 }}>
          <TableHead>
            <TableRow>
              {columns.map((col, idx) => (
                <TableCell key={idx}>
                  <strong>{col.replace(/_/g, " ")}</strong>
                </TableCell>
              ))}
            </TableRow>
          </TableHead>
          <TableBody>
            {rows.map((row, rowIdx) => (
              <TableRow key={rowIdx} hover>
                {columns.map((col, idx) => {
                  let value = row[col];
                  if (typeof value === "boolean") value = value ? "Yes" : "No";
                  if (value === null || value === undefined) value = "-";
                  return <TableCell key={idx}>{value}</TableCell>;
                })}
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </TableContainer>
    </div>
  );
};

export default AllDataTables;
