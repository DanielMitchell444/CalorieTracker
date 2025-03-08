import React from "react";
import DashboardHeader from "../Components/DashboardHeader";
import styles from '../App.module.css'
import ProgressBar from "../Components/ProgressBar";

const Tracker = ({toggle, toggleMenu, menuOpen, meals, handleInput, logout}) => {
 return (
<>

<DashboardHeader logout={logout} toggle={toggleMenu} menuOpen={menuOpen} />
<div className= {styles.trackerContainer}>
  <ProgressBar />
</div>
</>
 )
}

export default Tracker