import React from "react";
import styles from '../App.module.css'
import { Link } from "react-router-dom";

const LoginPage2 = ({handleChange, data}) => {
    return(
     <div>
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
              <div className={styles.inputFields2}>
                <input
                  type="password"
                  placeholder="Password"
                  name="email"
                  value={data.password}
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
                  <Link to = "/">Login</Link>
                </p>
              </div>
              <footer>
               <a href = "">Terms of Service</a>
               <hr></hr>
               <a href = "">Privacy Policy</a>
              </footer>
            </>
     </div>
    )
}

export default LoginPage2