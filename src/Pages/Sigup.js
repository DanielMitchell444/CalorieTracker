import React from 'react';
import styles from '../App.module.css';
import logo from '../Assets/logo.png';
import { Link } from 'react-router-dom';
import { useEffect } from 'react';
const SignUp = ({
  handleNext,
  steps,
  handleGoogleSignIn,
  data,
  handleChange,
  handleSignUp,
  handleBack,
  selectedValue,
  handleSelectedValue,
  handleProfileChange,
  errors,
  clearErrors
}) => {

  useEffect(() => {
    clearErrors();
  }, []);
  return (

    
    <div className={styles.wrappedContainer}>
      <div className={styles.logoStuff}>
        <img src={logo} className={styles.logo} alt="Logo" />
      </div>

      <div className={styles.containerSignUp}>
        {/* Dynamic Class for .content */}
        <div
          className={`${styles.content} ${
            steps === 1
              ? styles.contentStep1
              : steps === 2
              ? styles.contentStep2
              : styles.contentStep3
          }`}
        >
          <h1>Create an Account</h1>
        </div>
        <form className={styles.form} onSubmit={handleSignUp}>
          {errors && <p className={styles.errorMessage}>{errors}</p>}  {/* Display Error Message */}
          {steps === 1 && (
            <>
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
              <div className={styles.inputFields}>
                <input
                  type="submit"
                  value="Continue"
                  className={styles.login}
                />
              </div>
              <div className={styles.account}>
                <p className={styles.linkSign}>
                  Already have an account?
                  <Link to="/">Login</Link>
                </p>
              </div>
              <div className={styles.or}>
                <hr className={styles.thing} />
                <h2>Or</h2>
                <hr className={styles.thing} />
              </div>
              <div className={styles.alternativeSignIn}>
                <button
                  type="button"
                  className={styles.googleSignInButton}
                  onClick={handleGoogleSignIn}
                >
                  Sign up with Google
                </button>
                <button type="button" className={styles.microsoftSignInButton}>
                  Sign up with Microsoft
                </button>
                <button type="button" className={styles.googleSignInButton}>
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

    <div className={styles.inputFields}>
      <button
       type="submit"
       value="Go Back"
       className={styles.login3}
      >Go Back</button>
    </div>
   
    <footer>
      <a href="">Terms of Service</a>
      <hr />
      <a href="">Privacy Policy</a>
    </footer>
  </>
)}

          {steps === 3 && (
            <>
              <div className={styles.inputFields2}>
                <input type="text" placeholder="Height (cm)" 
                name = "height"
                onChange={handleProfileChange}
                value = {data.height}
                required />
              </div>
              <div className={styles.inputFields2}>
                <input type="text" placeholder="Weight (kg)" 
                name = "weight"
                required 
                onChange={handleProfileChange}
                value = {data.weight}
                />
              </div>
              <div className={styles.inputFields2}>
                <input type="text" placeholder="Age" 
                name = "age"
                value = {data.age}
                onChange={handleProfileChange}
                required />
              </div>
              <div className={styles.inputFields2}>
              <input type = "text"
              placeholder='Gender'
              name = "gender"
              onChange={handleProfileChange}
              value={data.gender}

              />
              </div>

              <div className={styles.inputFields2}>
                <input 
                type="text" 
                placeholder="First Name" 
                name = "firstName"
                onChange={handleChange}
                value = {data.firstName}
                required />
              </div>
              <div className={styles.inputFields}>
                <input
                  type="submit"
                  value="Continue"
                  className={styles.login}
                />
              </div>

              <div className={styles.account}>
                <p
                  className={styles.linkBack}
                  onClick={handleBack}
                >
                  Go Back
                </p>
              </div>
            </>
          )}
        </form>
        
      </div>

      
    </div>
  );
};

export default SignUp;
