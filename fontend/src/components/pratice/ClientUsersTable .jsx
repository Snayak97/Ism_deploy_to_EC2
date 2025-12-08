

import Axios from "../../api/Axios";

import React, { useEffect, useState } from "react";
import Box from "@mui/material/Box";
import Paper from "@mui/material/Paper";
import Table from "@mui/material/Table";
import TableBody from "@mui/material/TableBody";
import TableCell from "@mui/material/TableCell";
import TableContainer from "@mui/material/TableContainer";
import TableHead from "@mui/material/TableHead";
import TableRow from "@mui/material/TableRow";
import TablePagination from "@mui/material/TablePagination";
import TableSortLabel from "@mui/material/TableSortLabel";
import Toolbar from "@mui/material/Toolbar";
import Typography from "@mui/material/Typography";
import Checkbox from "@mui/material/Checkbox";
import IconButton from "@mui/material/IconButton";
import Tooltip from "@mui/material/Tooltip";
import FormControlLabel from "@mui/material/FormControlLabel";
import Switch from "@mui/material/Switch";
import DeleteIcon from "@mui/icons-material/Delete";
import FilterListIcon from "@mui/icons-material/FilterList";
import { alpha } from "@mui/material/styles";
import { visuallyHidden } from "@mui/utils";

// Helper functions
function descendingComparator(a, b, orderBy) {
  if (b[orderBy] < a[orderBy]) {
    return -1;
  }
  if (b[orderBy] > a[orderBy]) {
    return 1;
  }
  return 0;
}

function getComparator(order, orderBy) {
  return order === "desc"
    ? (a, b) => descendingComparator(a, b, orderBy)
    : (a, b) => -descendingComparator(a, b, orderBy);
}

// Table Head Component
function EnhancedTableHead(props) {
  const {
    onSelectAllClick,
    order,
    orderBy,
    numSelected,
    rowCount,
    onRequestSort,
    headCells,
  } = props;

  const createSortHandler = (property) => (event) => {
    onRequestSort(event, property);
  };

  return (
    <TableHead>
      <TableRow>
        <TableCell padding="checkbox">
          <Checkbox
            color="primary"
            indeterminate={numSelected > 0 && numSelected < rowCount}
            checked={rowCount > 0 && numSelected === rowCount}
            onChange={onSelectAllClick}
            inputProps={{ "aria-label": "select all users" }}
          />
        </TableCell>
        {headCells.map((headCell) => (
          <TableCell
            key={headCell.id}
            align={headCell.numeric ? "right" : "left"}
            padding={headCell.disablePadding ? "none" : "normal"}
            sortDirection={orderBy === headCell.id ? order : false}
          >
            <TableSortLabel
              active={orderBy === headCell.id}
              direction={orderBy === headCell.id ? order : "asc"}
              onClick={createSortHandler(headCell.id)}
            >
              {headCell.label}
              {orderBy === headCell.id ? (
                <Box component="span" sx={visuallyHidden}>
                  {order === "desc" ? "sorted descending" : "sorted ascending"}
                </Box>
              ) : null}
            </TableSortLabel>
          </TableCell>
        ))}
      </TableRow>
    </TableHead>
  );
}

// Toolbar Component
function EnhancedTableToolbar(props) {
  const { numSelected } = props;

  return (
    <Toolbar
      sx={[
        { pl: { sm: 2 }, pr: { xs: 1, sm: 1 } },
        numSelected > 0 && {
          bgcolor: (theme) =>
            alpha(
              theme.palette.primary.main,
              theme.palette.action.activatedOpacity
            ),
        },
      ]}
    >
      {numSelected > 0 ? (
        <Typography
          sx={{ flex: "1 1 100%" }}
          color="inherit"
          variant="subtitle1"
          component="div"
        >
          {numSelected} selected
        </Typography>
      ) : (
        <Typography
          sx={{ flex: "1 1 100%" }}
          variant="h6"
          id="tableTitle"
          component="div"
        >
          Client Users
        </Typography>
      )}

      {numSelected > 0 ? (
        <Tooltip title="Delete">
          <IconButton>
            <DeleteIcon />
          </IconButton>
        </Tooltip>
      ) : (
        <Tooltip title="Filter list">
          <IconButton>
            <FilterListIcon />
          </IconButton>
        </Tooltip>
      )}
    </Toolbar>
  );
}

// Table header columns
const headCells = [
  { id: "user_name", numeric: false, disablePadding: true, label: "User Name" },
  { id: "email", numeric: false, disablePadding: false, label: "Email" },
  {
    id: "department_name",
    numeric: false,
    disablePadding: false,
    label: "Department",
  },
  { id: "role_name", numeric: false, disablePadding: false, label: "Role" },
  {
    id: "mobile_number",
    numeric: false,
    disablePadding: false,
    label: "Mobile",
  },
  { id: "is_active", numeric: false, disablePadding: false, label: "Active" },
  {
    id: "last_active_date",
    numeric: false,
    disablePadding: false,
    label: "last active date",
  },
  {
    id: "last_deactive_date",
    numeric: false,
    disablePadding: false,
    label: "last deactive Date",
  },
  {
    id: "created_at",
    numeric: false,
    disablePadding: false,
    label: "Created At",
  },
];

export default function ClientUsersTable() {
  const [clientData, setClientData] = useState(null);
  const [users, setUsers] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  // Table states
  const [order, setOrder] = useState("asc");
  const [orderBy, setOrderBy] = useState("user_name");
  const [selected, setSelected] = useState([]);
  const [page, setPage] = useState(0);
  const [rowsPerPage, setRowsPerPage] = useState(5);
  const [dense, setDense] = useState(false);

  useEffect(() => {
    async function fetchData() {
      setLoading(true);
      setError(null);
      try {
        const response = await Axios.get("/client_user/list_client_users");
        setClientData(response.data.client_data);
        setUsers(response.data.users);
      } catch (err) {
        setError("Failed to fetch client users.");
        console.error("Failed to fetch client users", err);
      } finally {
        setLoading(false);
      }
    }
    fetchData();
  }, []);

  // Select all
  const handleSelectAllClick = (event) => {
    if (event.target.checked) {
      const newSelecteds = users.map((u) => u.user_id);
      setSelected(newSelecteds);
    } else {
      setSelected([]);
    }
  };

  // Select one
  const handleClick = (event, id) => {
    const selectedIndex = selected.indexOf(id);
    let newSelected = [];

    if (selectedIndex === -1) {
      newSelected = newSelected.concat(selected, id);
    } else if (selectedIndex === 0) {
      newSelected = newSelected.concat(selected.slice(1));
    } else if (selectedIndex === selected.length - 1) {
      newSelected = newSelected.concat(selected.slice(0, -1));
    } else if (selectedIndex > 0) {
      newSelected = newSelected.concat(
        selected.slice(0, selectedIndex),
        selected.slice(selectedIndex + 1)
      );
    }
    setSelected(newSelected);
  };

  // Sort request
  const handleRequestSort = (event, property) => {
    const isAsc = orderBy === property && order === "asc";
    setOrder(isAsc ? "desc" : "asc");
    setOrderBy(property);
  };

  // Pagination handlers
  const handleChangePage = (event, newPage) => {
    setPage(newPage);
  };

  const handleChangeRowsPerPage = (event) => {
    setRowsPerPage(parseInt(event.target.value, 10));
    setPage(0);
  };

  // Dense toggle
  const handleChangeDense = (event) => {
    setDense(event.target.checked);
  };

  // Check if selected
  const isSelected = (id) => selected.indexOf(id) !== -1;

  // Sorted & sliced rows for pagination
  const sortedRows = React.useMemo(() => {
    if (!users) return [];
    return users.slice().sort(getComparator(order, orderBy));
  }, [users, order, orderBy]);

  const visibleRows = React.useMemo(() => {
    return sortedRows.slice(
      page * rowsPerPage,
      page * rowsPerPage + rowsPerPage
    );
  }, [sortedRows, page, rowsPerPage]);

  return (
    <Box sx={{ width: "100%", padding: 2 }}>
      {/* Client Data Box */}
      <Paper sx={{ padding: 2, marginBottom: 3 }}>
        <Typography
          variant="h6"
          gutterBottom
          className="!font-semi-bold text-center"
        >
          Client Data
        </Typography>
        {loading && <Typography>Loading client data...</Typography>}
        {error && <Typography color="error">{error}</Typography>}
        {!loading && !error && clientData && (
          <>
            <Typography>
              <strong>Client ID:</strong> {clientData.client_id}
            </Typography>
            <Typography>
              <strong>Organization Name:</strong> {clientData.org_name}
            </Typography>
            <Typography>
              <strong>Organization Email:</strong> {clientData.org_email}
            </Typography>
            <Typography>
              <strong>Created At:</strong>{" "}
              {new Date(clientData.created_at).toLocaleString()}
            </Typography>
            <Typography>
              <strong>Updated At:</strong>{" "}
              {new Date(clientData.updated_at).toLocaleString()}
            </Typography>
          </>
        )}
      </Paper>

      {/* Users Table */}
      <Paper sx={{ width: "100%", mb: 2 }}>
        <EnhancedTableToolbar numSelected={selected.length} />
        <TableContainer>
          <Table sx={{ minWidth: 750 }} size={dense ? "small" : "medium"}>
            <EnhancedTableHead
              numSelected={selected.length}
              order={order}
              orderBy={orderBy}
              onSelectAllClick={handleSelectAllClick}
              onRequestSort={handleRequestSort}
              rowCount={users.length}
              headCells={headCells}
            />
            <TableBody>
              {loading && (
                <TableRow>
                  <TableCell colSpan={10} align="center">
                    Loading users...
                  </TableCell>
                </TableRow>
              )}
              {error && (
                <TableRow>
                  <TableCell colSpan={10} align="center" sx={{ color: "red" }}>
                    {error}
                  </TableCell>
                </TableRow>
              )}
              {!loading &&
                !error &&
                visibleRows.map((row, index) => {
                  const isItemSelected = isSelected(row.user_id);
                  const labelId = `enhanced-table-checkbox-${index}`;

                  return (
                    <TableRow
                      hover
                      onClick={(event) => handleClick(event, row.user_id)}
                      role="checkbox"
                      aria-checked={isItemSelected}
                      tabIndex={-1}
                      key={row.user_id}
                      selected={isItemSelected}
                      sx={{ cursor: "pointer" }}
                    >
                      <TableCell padding="checkbox">
                        <Checkbox
                          color="primary"
                          checked={isItemSelected}
                          inputProps={{ "aria-labelledby": labelId }}
                        />
                      </TableCell>
                      <TableCell
                        component="th"
                        id={labelId}
                        scope="row"
                        padding="none"
                      >
                        {row.user_name}
                      </TableCell>
                      <TableCell>{row.email}</TableCell>
                      <TableCell>{row.department_name}</TableCell>
                      <TableCell>{row.role_name}</TableCell>
                      <TableCell>{row.mobile_number}</TableCell>
                      <TableCell>{row.is_active ? "Yes" : "No"}</TableCell>
                      <TableCell>
                        {row.last_active_date
                          ? new Date(row.last_active_date).toLocaleString()
                          : "Not deactivated"}
                      </TableCell>
                      <TableCell>
                        {row.last_deactive_date
                          ? new Date(row.last_deactive_date).toLocaleString()
                          : "Not deactivated"}
                      </TableCell>
                      <TableCell>
                        {new Date(row.created_at).toLocaleString()}
                      </TableCell>
                    </TableRow>
                  );
                })}
              {/* Padding rows */}
              {!loading && !error && rowsPerPage - visibleRows.length > 0 && (
                <TableRow
                  style={{
                    height:
                      (dense ? 33 : 53) * (rowsPerPage - visibleRows.length),
                  }}
                >
                  <TableCell colSpan={10} />
                </TableRow>
              )}
            </TableBody>
          </Table>
        </TableContainer>
        <TablePagination
          rowsPerPageOptions={[5, 10, 25]}
          component="div"
          count={users.length}
          rowsPerPage={rowsPerPage}
          page={page}
          onPageChange={handleChangePage}
          onRowsPerPageChange={handleChangeRowsPerPage}
        />
      </Paper>

      <FormControlLabel
        control={<Switch checked={dense} onChange={handleChangeDense} />}
        label="Dense padding"
      />
    </Box>
  );
}
