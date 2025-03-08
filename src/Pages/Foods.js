import React from "react";
import DashboardHeader from "../Components/DashboardHeader";
import logo from '../Assets/logo.png'
import styles from '../App.module.css'

const Foods = ({toggle, toggleMenu, menuOpen, handleFoodData, meals, handleInput, logout, calorieData, handleCalorieChange,handleCalorieData, foods, handleFoodItemChange}) => {
    return(
    <div>
    <DashboardHeader logout={logout} menuOpen={menuOpen} />
     <div className = {styles.wrappedContainer2}>
      <div className= {styles.containerSignUp}>
        <div className= {styles.content}>
          <h1>Enter your food</h1>
        </div>
        <form className= {styles.foodsForm}
        onSubmit={handleFoodData}
        >
          <div className= {styles.inputFields2}>
          <input type = "text" 
          placeholder="Enter Food Item" 
          name = "name"
          value = {foods.name}
          onChange={handleFoodItemChange}
          />
          </div>

          <div className= {styles.inputFields2}>
          <input type = "text" 
          placeholder="Enter Calories" 
          name = "calories"
          value = {foods.calories}
          onChange={handleFoodItemChange}
          />
          </div>

          <div className= {styles.inputFields2}>
          <input type = "text" 
          placeholder="Enter Grams" 
          name = "grams"
          value = {foods.grams}
          onChange={handleFoodItemChange}
          />
          </div>
          <div className= {styles.inputFields2}>
          <input type = "text" placeholder="Enter Carbs"
          name = "carbs"
          value = {foods.carbs}
          onChange={handleFoodItemChange}
          />
          </div>

          <div className= {styles.inputFields2}>
          <input type = "text" 
          placeholder="Enter Fat" 
          name = "fat"
          value = {foods.fat}
          onChange={handleFoodItemChange}
          />
          </div>

          <div className= {styles.inputFields2}>
          <input type = "text" 
          placeholder="Enter Protein" 
          name = "protein"
          value = {foods.protein}
          onChange={handleFoodItemChange}
          />
          </div>

          <div className= {styles.inputFields}>
      <input type = "submit" value= "Continue" 
      className= {styles.login}
      />

      </div>
        </form>
      </div>
     </div>
     </div>
    )
}

export default Foods