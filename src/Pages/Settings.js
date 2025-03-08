import React from "react";
import DashboardHeader from "../Components/DashboardHeader";
const Settings = ({logout, toggle, toggleMenu, menuOpen,}) => {
 return (
 <div>
<DashboardHeader logout={logout} toggle={toggleMenu} menuOpen={menuOpen} />
 </div>
 )
}

export default Settings