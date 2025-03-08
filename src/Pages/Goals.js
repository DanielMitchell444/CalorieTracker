import styles from '../App.module.css';
import DashboardHeader from '../Components/DashboardHeader'
function Goals({toggle, toggleMenu, menuOpen, meals, handleInput, logout, calorieData, handleCalorieChange,handleCalorieData}) {
  return (
<>
    <DashboardHeader logout={logout} toggle={toggleMenu} menuOpen={menuOpen} />
    <div className={styles.container}>
      <div className={styles.formWrapper}>
        <h1 className={styles.title}>Edit Daily Goals</h1>
        <form className={styles.form} onSubmit={handleCalorieData}>
          <div className={styles.formGroup}>
            <label className={styles.label}>Daily Calorie Intake</label>
            <input type="number" placeholder="2000" className={styles.input}
            name = "calories"
            onChange={handleCalorieChange}
            value = {calorieData.calories}

            />
          </div>
          <div className={styles.formGroup}>
            <label className={styles.label}>Grams from Protein</label>
            <input type="number" placeholder="Enter Protein Calories"
            name = "caloriesProtein" 
            className={styles.input} 
            onChange = {handleCalorieChange}
            value = {calorieData.caloriesProtein}
            />
          </div>
          <div className={styles.formGroup}>
            <label className={styles.label}>Grams from Carbs</label>
            <input type="number" 
            placeholder="Enter Carbs Calories" 
            name = "caloriesCarbs"
            className={styles.input} 
            onChange = {handleCalorieChange}
            value = {calorieData.caloriesCarbs}
            />
          </div>
          <div className={styles.formGroup}>
            <label className={styles.label}>Calories from Fat</label>
            <input type="number" placeholder="Enter Fat Calories" 
            name = "caloriesFat"
            className={styles.input} 
            onChange = {handleCalorieChange}
            value = {calorieData.caloriesFat}
            />
          </div>
          <button type="submit" className={styles.button}>Save Goals</button>
        </form>
      </div>
    </div>
    </>
  );
}

export default Goals