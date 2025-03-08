import React, { use, useState } from "react";
import styles from '../App.module.css'
import DashboardHeader from "../Components/DashboardHeader";
import DaysOfWeek from "../Components/Days";
import ProgressBar from "../Components/ProgressBar";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { faBullseye } from "@fortawesome/free-solid-svg-icons";
import { Link } from "react-router-dom";
import { faDumbbell } from "@fortawesome/free-solid-svg-icons";
import { faPerson } from "@fortawesome/free-solid-svg-icons";
import Calendar from "../Components/Calendar";

const Dashboard = ({ logout, toggle, toggleMenu, menuOpen, setMenusOpen }) => {
  const [progress, trackProgress] = useState(20);

  const [setMenu, setMenuOpen] = useState(false)

 let first_name = localStorage.getItem('first_name')


 const handleMenuToggle = () => {
  setMenuOpen(!setMenu)
 }

  return (
    <>
     <DashboardHeader 
  logout={logout} 
  toggle={() => setMenuOpen(!menuOpen)} 
  menuOpen={menuOpen} 
  toggleMenu={toggleMenu} 
  handleMenuToggle = {handleMenuToggle}
/>
      <div className={styles.dashboardContainer}>
      <h1>Welcome {first_name} </h1>
      <div className= {styles.cardContainer}>
      <div className= {styles.cards}>
        <div className= {styles.cardsWrapper}>
      <Link to = "/Foods" className= {styles.links}>
        <h1>Enter your Food</h1>
        <p>Enter the food you ate today</p>
        <FontAwesomeIcon

        icon = {faBullseye}
        className= {styles.icon}

        />

        </Link>
        </div>
        </div>
        <div className= {styles.cards}>
          <Link to = "/Goals" className= {styles.links}>
          <div className= {styles.cardsWrapper}>

      <h1>Set Your Calorie Goals</h1>

      <p>Define your calorie targets and stay on track.</p>

      <FontAwesomeIcon

icon = {faDumbbell}

className= {styles.icon}

/>
    </div>

    </Link>

    </div>

    <div className= {styles.cards}>
  <Link to = "/Calories" className= {styles.links}>
    <div className= {styles.cardsWrapper}>

<h1>Track Your Calories</h1>

<p>Log your meals and maintain a balanced diet.</p>

<FontAwesomeIcon

icon = {faDumbbell}

className= {styles.icon}

/>
</div>
</Link>
      </div>
    </div>

    </div>
       

     
    </>
    )
}

export default Dashboard