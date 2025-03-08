import React from "react";
import styles from '../App.module.css'
import logo from '../Assets/logo.png'
const DashboardMenu = () => {
    return(
    <nav className= {styles.DashboardMenu}>
    <Link to = "/Dashboard">Home</Link>
    <Link to = "/Tracker">Tracker</Link>
    <Link to = "/Settings">Settings</Link>

    </nav>
    )
}

export default DashboardMenu