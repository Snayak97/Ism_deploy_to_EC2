import { RxDashboard } from "react-icons/rx";
import { FaDatabase } from "react-icons/fa6";
import { MdOutlineProductionQuantityLimits } from "react-icons/md";
import { BsArrowDownUp } from "react-icons/bs";
import { FaUserLarge,FaUserShield } from "react-icons/fa6";

export const sidebarConfig = {
  super_admin: [
    { icon: <RxDashboard />, text: "DashBoard", link: "/clientadmin/dashboard" },
    { icon: <FaDatabase />, text: "UploadMasters", link: "/clientadmin/uploadmasters" },
    { icon: <MdOutlineProductionQuantityLimits />, text: "Products", link: "/clientadmin/products" },
    { icon: <BsArrowDownUp />, text: "Transactions", link: "/clientadmin/transaction" },
    { icon: <FaUserLarge />, text: "Users", link: "/clientadmin/AllClientAndNormalUsers" },
    { icon: <FaUserShield />, text: "Permission", link: "/clientadmin/Permission" },
  ],
  client_admin: [
    { icon: <RxDashboard />, text: "DashBoard", link: "/clientadmin/dashboard" },
    { icon: <FaDatabase />, text: "UploadMasters", link: "/clientadmin/uploadmasters" },
    { icon: <MdOutlineProductionQuantityLimits />, text: "Products", link: "/clientadmin/products" },
    { icon: <BsArrowDownUp />, text: "Transactions", link: "/clientadmin/transaction" },
    { icon: <FaUserLarge />, text: "Users", link: "/clientadmin/users" },
  ],
  manager: [
    { icon: <RxDashboard />, text: "DashBoard", link: "/clientadmin/dashboard" },
    { icon: <FaDatabase />, text: "UploadMasters", link: "/clientadmin/uploadmasters" },
    { icon: <MdOutlineProductionQuantityLimits />, text: "Products", link: "/clientadmin/products" },
    { icon: <BsArrowDownUp />, text: "Transactions", link: "/clientadmin/transaction" },
  ],
  employee: [
    { icon: <RxDashboard />, text: "DashBoard", link: "/clientadmin/dashboard" },
    { icon: <FaDatabase />, text: "UploadMasters", link: "/clientadmin/uploadmasters" },
   
  ],
  it_admin: [
    { icon: <RxDashboard />, text: "DashBoard", link: "/clientadmin/dashboard" },
    { icon: <FaUserLarge  />, text: "Users", link: "/clientadmin/users" },

  ],
  normal_user: [
    { icon: <MdOutlineProductionQuantityLimits />, text: "Products", link: "/clientadmin/products" },
    
  ],
};