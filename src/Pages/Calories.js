import React, { use } from "react";
import DashboardHeader from "../Components/DashboardHeader";

import { useState } from "react";

import styles from '../App.module.css'
function Calories({calorieData, logout, toggleMenu, menuOpen}) {
  const [calories, setCalories] = useState(localStorage.getItem('total_calories'));
  const [protein, setProtein] = useState(localStorage.getItem('target_protein'))
  const [carbs, setCarbs] = useState(localStorage.getItem('target_carbs'))
  const [goal, setGoal] = useState(localStorage.getItem('target_calories'));
  const [fat, setFat] = useState(localStorage.getItem('fat'))


  return (
    <>
    <DashboardHeader logout={logout} toggle={toggleMenu} menuOpen={menuOpen} />
    <div className= {styles.caloriesWrapper}>
    <div className={styles.container3}>
      <h1 className={styles.title}>Calorie Tracker</h1>
      <div className={styles.progressBarContainer}>
        <div 
          className={styles.progressBar} 
          style={{ width: `${(calories / goal) * 100}%` }}
        ></div>
      </div>
      <p className={styles.calorieInfo}>{calories} / {goal} cal</p>
      </div>
    </div>
    <div className= {styles.cardsContainer}>
    <div className= {styles.cards}>
    <div className= {styles.cardsWrapper}>
      <h1>Carbs Today: {carbs}g</h1>
    </div>
    </div>
    </div>

    <div className= {styles.cardsContainer}>
    <div className= {styles.cards}>
    <div className= {styles.cardsWrapper}>
      <h1>Fat Today: {fat}g</h1>
    </div>
    </div>
    </div>

    <div className= {styles.cardsContainer}>
    <div className= {styles.cards}>
    <div className= {styles.cardsWrapper}>
      <h1>Protein Today: {protein}g</h1>
    </div>
    </div>
    </div>

    <div className= {styles.cardsContainer}>
    <div className= {styles.cards}>
    <div className= {styles.cardsWrapper}>
      <h1>Carbs Today: {}</h1>
    </div>
    </div>
    </div>
      </>
  );
}

export default Calories