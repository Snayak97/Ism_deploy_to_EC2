import React, { useState } from "react";
import Button from "@mui/material/Button";
import Menu from "@mui/material/Menu";
import MenuItem from "@mui/material/MenuItem";
import ListItemIcon from "@mui/material/ListItemIcon";
import { Link } from "react-router-dom";

import PersonAdd from "@mui/icons-material/PersonAdd";
import Settings from "@mui/icons-material/Settings";

import Divider from "@mui/material/Divider";
import LogOut from "../../pages/auth/LogOut/LogOut";
const fallbackAvatar =
  "https://images.pexels.com/photos/941693/pexels-photo-941693.jpeg?auto=compress&cs=tinysrgb&dpr=2&w=500";

const UserMenu = ({ user }) => {
  const [anchorEl, setAnchorEl] = useState(null);
  const myAccopen = Boolean(anchorEl);
  const handleClick = (event) => {
    setAnchorEl(event.currentTarget);
  };
  const handleClose = () => {
    setAnchorEl(null);
  };
  return (
    <div className="">
      <Button
        className=" !rounded-full !overflow-hidden p-0"
        onClick={handleClick}
      >
        <img
          src={fallbackAvatar}
          alt=""
          className="w-10 h-10  rounded-full object-cover"
        />
      </Button>
      <Menu
        anchorEl={anchorEl}
        id="account-menu"
        open={myAccopen}
        onClose={handleClose}
        onClick={handleClose}
        slotProps={{
          paper: {
            elevation: 0,
            className:"dark:!shadow-md dark:!bg-neutral-900 dark:!text-white dark:!shadow-white  ",

            sx: {
              overflow: "visible",
              filter: "drop-shadow(0px 2px 8px rgba(0,0,0,0.32))",
              mt: 1.5,
              "& .MuiAvatar-root": {
                width: 32,
                height: 32,
                ml: -0.5,
                mr: 1,
    
              },
              "&::before": {
                content: '""',
                display: "block",
                position: "absolute",
                top: 0,
                right: 14,
                width: 10,
                height: 10,
                bgcolor: "background.paper",
                transform: "translateY(-50%) rotate(45deg)",
                zIndex: 0,
              },
            },
          },
        }}
        transformOrigin={{ horizontal: "right", vertical: "top" }}
        anchorOrigin={{ horizontal: "right", vertical: "bottom" }}
       
      >
        <MenuItem onClick={handleClose} className="!cursor-default dark:hover:!bg-gray-100 dark:hover:!text-black   ">
          <ListItemIcon>
            <img
              src={user?.avatarUrl || fallbackAvatar}
              alt="user_name"
              className="w-8 h-8 rounded-full object-cover"
            />
          </ListItemIcon>
          <div className="flex flex-col items-start ml-2">
            <span className="text-md font-semibold">
              {user?.user_name || "User"}
            </span>
            <span className="text-sm">{user?.email || "user@gmail.com"}</span>
          </div>
        </MenuItem>
        <Divider className="dark:bg-white" />
        <Link to="/clientadmin/userProfiles">
          <MenuItem onClick={handleClose} className="dark:hover:!bg-gray-100 dark:hover:!text-black ">
            <ListItemIcon >
              <PersonAdd fontSize="small" className="dark:text-yellow-300  " />
            </ListItemIcon>
            My account
          </MenuItem>
        </Link>
        <MenuItem onClick={handleClose} className="dark:hover:!bg-gray-100 dark:hover:!text-black ">
          <ListItemIcon  >
            <Settings fontSize="small " className="dark:text-yellow-300  " />
          </ListItemIcon>
          Settings
        </MenuItem>

        <div className="flex item-center justify-center  mt-1">
          <LogOut />
        </div>
      </Menu>
    </div>
  );
};

export default UserMenu;
