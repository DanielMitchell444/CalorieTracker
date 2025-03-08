import logo from './logo.svg';
import styles from '../src/App.module.css'
import SignUp from './Pages/Sigup';
import axios from 'axios';
import { use, useState } from 'react';
import { Link, Route, Router, Routes } from 'react-router-dom';
import {auth, googleProvider, signInWithPopup} from '../src/Services/firebase'
import Login from '../src/Pages/Login'
import Dashboard from './Pages/Dashboard';
import Tracker from './Pages/Tracker';
import Sides from './Pages/Sides';
import PrivateRoute from './Components/PrivateRoute';
import Goals from './Pages/Goals';
import Settings from './Pages/Settings';
import Setup from './Pages/Setup';
import Calories from './Pages/Calories';
import Foods from './Pages/Foods';
function App() {


  const isAuthenticated = !!localStorage.getItem('auth_token');

  const [total_calories, setTotalCalories] = useState(localStorage.getItem('total_calories'))

  
  const [menuOpen, setMenuOpen] = useState(false);


  const [steps, nextSteps] = useState(1)
  const [meals, setMeals] = useState("")
  const [signUpData, setSignUpData] = useState({
   email: "",
   password: "",
   age: "",
   height: "",
   weight: "",
   firstName: ""
  })

  const [calorieData, setCalorieData] = useState([{
    calories: "",
    caloriesProtein: "",
    caloriesFat: "",
    caloriesCarbs: ""
  }])
  




  const [food, setFood] = useState({
   name: "",
   calories: "",
   protein: "",
   fat: "",
   grams: ""
  })


  const [progress, setProgress] = useState(10)
  const [menuOpens, setMenuOpens] = useState(false);

  const [setupSteps, setSetupSteps] = useState(1)

  
  const [toggle, setToggle] = useState(false)

  const [inputChange, handleInputChange] = useState("")


  const [selectedValue, setSelectedValue] = useState("")


  const [loginData, setLoginData] = useState({
    email: "",
    password: ""
  })

  const [goals, setGoals] = useState({
   goals: ""
  })

  const [errors, setErrors] = useState("")


  const getProgress = () => {
    setProgress(0)
  }

  const [weight, setWeight] = useState("")


  const handleGoogleSignIn = async () => {
      try {
        const result = await signInWithPopup(auth, googleProvider);
        const token = await result.user.getIdToken();
        const response = await fetch("http://localhost:8000/api/auth/token/", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({ token }),
        });
        const data = await response.json();
        console.log("Backend Response:", data);
        
        if (data.is_first_time_login) {
          // Handle first-time login, e.g., redirect to a setup page or show a welcome message
          window.location.href = "/Setup";
        } else {
          window.location.href = "/Dashboard";  // Normal redirect to the dashboard
        }
    
      } catch (error) {
        console.error("Error signing in with Google:", error);
      }
    };


    const handleSelectedValue = (e) => {
      setSelectedValue(e.target.value)
    }

     const getData = async () => {

    fetch('"https://platform.fatsecret.com/rest/food/autocomplete/v2"')
      .then(response => response.json())
      .then(data => {
        setMeals(data)
      })
  }



  const handleSignIn = async (e) => {
    e.preventDefault();
  
    if (steps === 1) {
      try {
        const response = await axios.post("http://localhost:8000/api/login/", {
          email: loginData.email,
        });
  
        console.log("Login Response:", response.data); // Debugging
        nextSteps((step) => step + 1);
      } catch (error) {
        console.log("Login failed:", error.response.data.message);
        setErrors(error.response.data.message)
      }
    } else if (steps === 2) {
      try {
        const response = await axios.post("http://localhost:8000/api/validate_user/", {
          email: loginData.email,
          password: loginData.password
        });
  
        console.log("Validate User Response:", response.data); // Debugging
  
        const token = response.data.token;
        const first_name = response.data.first_name;
        const first_time_login = response.data.first_time_login;
        const goal = response.data.goals;
        const target_carbs = response.data.carbs
        const target_protein = response.data.protein
        const target_fat = response.data.fat
        const no = response.data.no
        const target_calories = response.data.calories
        const total_calories = response.data.total_calories

        console.log(target_calories)
        console.log(total_calories)


  
        if (token) {
          // Store user data
          localStorage.setItem("auth_token", token);
          localStorage.setItem('email', loginData.email)

          localStorage.setItem("target_carbs", target_carbs)
          localStorage.setItem('target_protein', target_protein)
          localStorage.setItem('target_fat', target_fat)
          localStorage.setItem('target_calories', target_calories)
          localStorage.setItem("first_name", first_name);
          localStorage.setItem("goal", goal);
          localStorage.setItem('no', no)
          localStorage.setItem("total_calories", total_calories)
  
          console.log("Login Successful:", response.data);
          localStorage.setItem("first_time_login", first_time_login)
  
          if (first_time_login ===  "") {
            window.location.href = "/Setup";  
          } else {
            window.location.href = "/Dashboard";
          }
        }
      } catch (error) {
        console.log("Login failed:", error);
      }
    }
  };    

const toggleMenus = () => {
  setMenuOpens(!menuOpens);
};

          const handleLogout = async () => {
            const token = localStorage.getItem('auth_token');  // Get the token from localStorage
        
            if (token) {
              try {
                // Send POST request to the logout endpoint
                const response = await axios.post('http://localhost:8000/api/logout/', {}, {
                  headers: {
                    'Authorization': `Token ${token}`  // Attach the token to the Authorization header
                  }
                });
        
                console.log(response.data);  // Log the response message
        
                // If successful, remove the token from localStorage
                localStorage.removeItem('auth_token');
                localStorage.removeItem('first_name')
        
                // Optionally redirect to the login page
                window.location.href = '/';  // Redirect to login page or any other page
        
              } catch (error) {
                console.log('Error logging out:', error);
              }
            } else {
              console.log('No token found. Already logged out.');
            }
          };
        


          const toggleMenu = () => {
            setMenuOpen((prev) => !prev);
          };
        


    const handleSignUp = async (e) => {
      e.preventDefault();
    
      if (steps === 1) {
        try {
          const response = await axios.post("http://localhost:8000/api/register_email/", {
            email: signUpData.email,
          });
    
          console.log(response.data); // Logs success data
          nextSteps(next => next + 1); // Moves to step 2 (steps will be incremented by 1)
          console.log(steps)
        } catch (error) {
        setErrors(error.response.data.message)
          console.log('This did not work!', error);
        }
    
       } else if (steps === 2) {
        try {
          const response = await axios.post("http://localhost:8000/api/register_details/", {
            email: signUpData.email,
            password: signUpData.password,
          });
    
          console.log(response.data); // Logs success data
          nextSteps(steps + 1); // Moves to step 3
          console.log(steps)
        } catch (error) {
          setErrors(error.response?.data || { general: 'Details registration failed' });
          console.log('This does not work', error);
        }
      } else if (steps === 3) {
        try {
          const response = await axios.post("http://localhost:8000/api/register_profile/", {
            email: signUpData.email,
            password: signUpData.password,
            age: signUpData.age,
            weight: signUpData.weight,
            height: signUpData.height,
            gender: signUpData.gender,
            firstName: signUpData.firstName

          });
    
          console.log(response.data); // Logs success data

          window.location.href = "/"
          nextSteps(1)
        } catch (error) {
          setErrors(error.response?.data || { general: 'Details registration failed' });
          console.log('This does not work', error);
          console.log(error.response.data)
        }

      }
    };

  const handleInput = (e) => {
   handleInputChange(e.target.value)
  }
  const handleNext = () => {
    nextSteps(steps + 1)
  }

  const handleBack = () => {
    nextSteps(steps - 1);
  }


  const handleChange = (e) => {
    const { name, value } = e.target;
    setSignUpData({ ...signUpData, [name]: value });
};


const handleClick = async (goal) => {
  const token = localStorage.getItem("auth_token");

  try {
    const response = await fetch("http://localhost:8000/api/register_goals", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Token ${token}`,
      },
      body: JSON.stringify(goal), // Send plain string
    });

    if (response.ok) {
      console.log("Goal saved successfully!");
      window.location.href = "/Dashboard"

      localStorage.setItem('goal', goal)
    } else {
      console.error("Error saving goal:", response.statusText);
    }
  } catch (error) {
    console.error("Error:", error);
  }
};
const handleProfileChange = (e) => {
  const { name, value } = e.target;
  setSignUpData({ ...signUpData, [name]: value });
}

const handleLoginChange = (e) => {
  const { name, value } = e.target;
  setLoginData({ ...loginData, [name]: value }); // Fix here: use loginData
};

const handleCalorieChange = (e) => {
  const {name, value} = e.target

  setCalorieData({...calorieData, [name]: value})
  
}


const handleFoodItemChange = (e) => {
  const {name, value} = e.target
  setFood({...food, [name]: value})
}

const handleCalorieData = async (e) => {
  e.preventDefault()
  let auth_token = localStorage.getItem('auth_token')
  console.log(auth_token)
 try{
  const response = await axios.post('http://localhost:8000/api/register_daily_goals/',
    {
      email: localStorage.getItem('email'),
      target_calories: calorieData.calories,
      target_carbs: calorieData.caloriesCarbs,
      target_fat: calorieData.caloriesFat,
      target_protein: calorieData.caloriesProtein,

    },
    {

    headers: {
      'Authorization': `Token ${localStorage.getItem('auth_token')}`,
    }

    
  },


  )

  setCalorieData({
    target_calories: calorieData.calories,
    target_carbs: calorieData.caloriesCarbs,
    target_fat: calorieData.caloriesFat,
    target_protein: calorieData.caloriesProtein,
  })
  localStorage.setItem('target_calories', calorieData.target_calories)
  localStorage.setItem('target_carbs', calorieData.target_carbs)
  localStorage.setItem('target_fat', calorieData.target_fat)
  localStorage.setItem('target_protein', calorieData.target_protein)
  window.location.href = "/Dashboard"
} catch (error){
  console.log('error:', error.response) 
}
 }

const logout = async () => {
  try {
      const response = await axios.post('http://localhost:8000/api/logout/', {}, {
          headers: {
              'Authorization': `Token ${localStorage.getItem('token')}`,
          },
      });
      console.log(response.data);
      // Clear token and redirect to login page
      localStorage.removeItem('token');
      localStorage.removeItem('total_calories')
      localStorage.removeItem('calories')
      localStorage.removeItem('calories')
      window.location.href = '/login';
  } catch (error) {
      console.error("Error logging out:", error.response);
  }
};


const handleFoodItems = async (e) => {

  e.preventDefault()


  // Get the current total calories from localStorage, or default to 0 if it doesn't exist
  const currentTotalCalories = parseInt(localStorage.getItem('calories')) || 0;

  // Calculate the new total calories
  const newTotalCalories = currentTotalCalories + parseInt(food.calories);
  try {
    const response = await axios.post('http://localhost:8000/api/register_food', {
      email: localStorage.getItem('email'),
      calories: food.calories,
      fat: food.fat,
      grams: food.grams,
      name: food.name,
      carbs: food.carbs,
      protein: food.protein,
      total_calories: newTotalCalories
    });
    console.log(response);

    localStorage.setItem('calories', food.calories)
    localStorage.setItem('total_calories', newTotalCalories)
    localStorage.setItem('fat', food.fat)
  } catch (error) {
    console.log(error.response?.data || error.message);
  }
};


const clearErrors = () => {
  setErrors("")
}

  return (
    <div className="App">

<Routes>
      <Route  path = "/" element= {
        <Login
        handleNext={handleNext}
        errors = {errors}
        steps = {steps}
        data = {loginData}
        clearErrors={clearErrors}
        handleChange = {handleLoginChange}
        handleLogin = {handleSignIn}
        handleGoogleSignIn = {handleGoogleSignIn}
        />
      }

      />

<Route  path = "/SignUp" element= {
          

          <SignUp
          handleNext={handleNext}
          steps = {steps}
          data = {signUpData}
          errors = {errors}
          setErrors = {setErrors}
          selectedValue = {selectedValue}
          handleSelectedValue = {handleSelectedValue}
          clearErrors = {clearErrors}
          handleChange = {handleChange}
          handleSignUp = {handleSignUp}
          handleProfileChange = {handleProfileChange}
          handleGoogleSignIn = {handleGoogleSignIn}
          />
      }

      />

  <Route path = "/Settings" element = {
   <PrivateRoute isAuthenticated={isAuthenticated}>
    <Settings
    toggle = {toggle}
    toggleMenu = {toggleMenu}
    menuOpen = {menuOpen}

    />
   </PrivateRoute>

  }

  />

<Route path = "/Dashboard" element = {
  <PrivateRoute isAuthenticated={isAuthenticated}>
  <Dashboard 
  toggle = {toggle}
  toggleMenu = {toggleMenu}
  menuOpen = {menuOpen}
  progress = {progress}
  logout = {handleLogout}
  setMenuOpen={setMenuOpen}
  setMenuOpens = {setMenuOpens}


  />

</PrivateRoute>

}

/>

<Route path = "/Tracker" element = {
  <PrivateRoute isAuthenticated={isAuthenticated}>
  <Tracker 
  toggle = {toggle}
  toggleMenu = {toggleMenu}
  menuOpen = {menuOpen}
  getMealData = {getData}
  logout={handleLogout}
  total_calories = {total_calories}
  />
  </PrivateRoute>
}

/>

<Route path = '/Sides' element = {
  <Sides />

}

/>

<Route path = "/Goals" element = {
  <PrivateRoute isAuthenticated={isAuthenticated}>
    <Goals
    toggle = {toggle}
    toggleMenu = {toggleMenu}
    menuOpen = {menuOpen}
    logout={handleLogout}
    goals = {goals}
    handleClick={handleClick}
    calorieData = {calorieData}
    handleCalorieChange = {handleCalorieChange}
    handleCalorieData = {handleCalorieData}
    />
  </PrivateRoute>
}

/>


<Route path = "/Setup" element = {
  <PrivateRoute isAuthenticated= {isAuthenticated}>
    <Setup 
    handleClick = {handleClick}
    steps = {setupSteps}
    />
  </PrivateRoute>
}

/>

<Route path = "/Calories" element = {
  <PrivateRoute isAuthenticated={isAuthenticated}>
  <Calories 
  caloriesData = {calorieData}
  logout={logout}
  toggleMenu={toggleMenu}
  menuOpen={menuOpen}
  />
  </PrivateRoute>
}

/>

<Route path = "/Foods" element = {
  <PrivateRoute isAuthenticated={isAuthenticated}>
   <Foods 
     caloriesData = {calorieData}
     logout={logout}
     toggleMenu={toggleMenu}
     menuOpen={menuOpen}
     foods = {food}
     handleFoodItemChange = {handleFoodItemChange}
     handleFoodData = {handleFoodItems}
   />
  </PrivateRoute>
}

/>

      </Routes>
   
    </div>
  );
}

export default App;
