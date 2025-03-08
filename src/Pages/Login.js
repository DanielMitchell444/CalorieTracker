
import styles from '../App.module.css'
import logo from '../Assets/logo.png'
import { useEffect } from 'react'
import { Link } from 'react-router-dom'
const Login = ({steps, data, handleLogin, handleChange, handleGoogleSignIn, errors, clearErrors}) => {
     useEffect(() => {
        clearErrors();
      }, []);
 return(

  
  <>
<div className= {styles.wrappedContainer}>
<div className= {styles.logoStuff}>
  <img src = {logo} className= {styles.logo} />
  </div>
<div className =  {styles.containerSignUp}>
  
 <div className= {styles.content}>
  {steps == 1 ?
   <h1>Welcome Back!</h1>
   : <h1>Enter your password</h1>
  }
   </div>
   <form 
   //This is code to try and get this to github
   className= {styles.form}
   onSubmit={handleLogin}
   >
    {steps === 1 && (
    <>
  
  {errors && <p className={styles.errorMessage}>{errors}</p>}  {/* Display Error Message */}
    <div className= {styles.inputFields2}>
      <input type = "email" 
      placeholder="Enter Email"
       required 
       name = "email"
       value = {data.email}
       onChange={handleChange}
       />
    </div>
    <div className= {styles.inputFields}>
      <input type = "submit" value= "Continue" 
      className= {styles.login}
      />
    </div>
    <div className= {styles.account}>
        <p>Don't have an account? 
         <Link to = "/Signup" onClick={clearErrors}>Signup</Link>
          
          </p>
      </div>
      <div className= {styles.or}>
        <hr className= {styles.thing}></hr>
        <h2>Or</h2>
        <hr className= {styles.thing}></hr>
      </div>
      <div className= {styles.alternativeSignIn}>
        <button type = "button"
        className= {styles.googleSignInButton}
        onClick={handleGoogleSignIn}

        >
       Sign in with Google
        </button>
        <button type = "button"
        className= {styles.microsoftSignInButton}
        >
         Sign in with Microsoft
        </button>
        <button type = "button"
        className= {styles.googleSignInButton}
        >
         Sign in with Memes
        </button>
      </div>

      <footer>
      <a href="">Terms of Service</a>
      <hr />
      <a href="">Privacy Policy</a>
    </footer>
      </>
    )}

{steps === 2 && (
  <>
    <div className={styles.step2FieldsWrapper}>
      <div className={styles.inputFields2}>
        <input
          type="email"
          placeholder="Email"
          name="email"
          value={data.email}
          onChange={handleChange}
          required
        />
      </div>
      <div className={styles.inputFields2}>
        <input
          type="password"
          placeholder="Password"
          name="password"
          value={data.password}
          onChange={handleChange}
          required
        />
      </div>
    </div>
    <div className={styles.inputFields}>
      <input
        type="submit"
        value="Continue"
        className={styles.login}
      />
    </div>

    <div className= {styles.or}>
        <hr className= {styles.thing}></hr>
        <h2>Or</h2>
        <hr className= {styles.thing}></hr>
      </div>
      <div className= {styles.alternativeSignIn}>
        <button type = "button"
        className= {styles.googleSignInButton}
        onClick={handleGoogleSignIn}

        >
       Sign in with Google
        </button>
        <button type = "button"
        className= {styles.microsoftSignInButton}
        >
         Sign in with Microsoft
        </button>
        <button type = "button"
        className= {styles.googleSignInButton}
        >
         Sign in with Memes
        </button>
      </div>
   
    <footer>
      <a href="">Terms of Service</a>
      <hr />
      <a href="">Privacy Policy</a>
    </footer>
  </>
)}


    
   </form>
 </div>

</div>
</>
 )
}

export default Login