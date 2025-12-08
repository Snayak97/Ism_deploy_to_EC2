import React from "react";
import ChangePasswords from "./ChangePasswords";
import RecoveryPasswords from "./RecoveryPasswords";



const PasswordSections = () => {
  

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 gap-8 mt-10 ">
      <RecoveryPasswords/>
      {/* --- Change Password --- */}
      <ChangePasswords/>
    </div>
  );
};

export default PasswordSections;
