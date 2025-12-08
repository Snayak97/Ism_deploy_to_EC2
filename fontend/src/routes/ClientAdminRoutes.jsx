import { Route } from "react-router-dom";
import ClientAdminLayout from "../layouts/ClientAsminLayout/ClientAdminLayout";

import ClientAdmin from "../pages/clientadmin/ClientAdmin";
import Products from "../pages/product/Products";
import Transaction from "../pages/transaction/Transaction";
import UploadMasterData from "../pages/masterupload/UploadMasterData";
import MarketplaceMaster from "../pages/markeplaceMasterpages/MarketplaceMaster";
import SellingPlatformsMaster from "../pages/sellingpatformsMasterpages/SellingPlatformsMaster";
import PlatformMaster from "../pages/platformMasterpags/PlatformMaster";
import ShippingLocationsMaster from "../pages/shippinglocationMaster/ShippingLocationsMaster";
import RequireAuth from "./protectRoute/RequiredAuth";
import ClientUser from "../pages/clientuser/ClientUser";
import UserManagement from "../pages/Superadminpages/allUsers/UserManagement";
import UserProfiles from "../pages/userProfiles/UserProfiles"
import PermissionPage from "../pages/auth/permisions/PermissionPage";

export const ClientAdminRoutes = (
  <Route
    element={
      <RequireAuth>
        <ClientAdminLayout />
      </RequireAuth>
    }
  >
    <Route path="/clientadmin/dashboard" element={<ClientAdmin />} />
    <Route path="/clientadmin/products" element={<Products />} />
    <Route path="/clientadmin/transaction" element={<Transaction />} />
    <Route path="/clientadmin/users" element={<ClientUser/>} />
    <Route path="/clientadmin/AllClientAndNormalUsers" element={<UserManagement/>} />
    <Route path="/clientadmin/Permission" element={<PermissionPage/>} />
    <Route path="/clientadmin/userProfiles" element={<UserProfiles/>} />
    <Route path="/clientadmin/uploadmasters" element={<UploadMasterData />} />

    {/* Master Data routes */}
    <Route path="masterdata">
      <Route path="marketplaces" element={<MarketplaceMaster />} />
      <Route path="selling-platforms" element={<SellingPlatformsMaster />} />
      <Route path="platforms-master" element={<PlatformMaster />} />
      <Route path="shipping-locations" element={<ShippingLocationsMaster />} />
    </Route>
  
  
  </Route>
);
