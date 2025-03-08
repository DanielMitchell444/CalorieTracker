import React from 'react';
import styles from '../App.module.css';
import logo from '../Assets/logo.png'; // Import your logo
import { faBars } from '@fortawesome/free-solid-svg-icons';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { Link } from 'react-router-dom';

const DashboardHeader = ({ logout, toggle, menuOpen, toggleMenu }) => {
  return (
    <>
      <div className={styles.headerContainer}>
        <header className={styles.header}>
          {/* Desktop Navigation (visible on larger screens) */}
          <nav className={styles.navLinks}>
            <Link to="/Dashboard">Dashboard</Link>
            <Link to="/Calories">Track Calories</Link>
            <Link to="/Foods">Enter Meals</Link>
            <Link to="/Goals">Set Calorie Goal</Link>
            <Link to="/Settings">Settings</Link>
            <button onClick={logout} className={styles.menuLogoutButton}>
              Logout
            </button>
          </nav>

          {/* Hamburger menu (visible only on small screens) */}
          <FontAwesomeIcon
            icon={faBars}
            className={styles.bars}
            onClick={toggle}
          />
        </header>
      </div>

      {/* Mobile Slide-out menu */}
      {menuOpen && (
        <div className={styles.slideOutMenu}>
          <ul>
            <li><Link to="/Dashboard" onClick={toggle}>Dashboard</Link></li>
            <li><Link to="/Calories" onClick={toggle}>Track Calories</Link></li>
            <li><Link to="/Progress" onClick={toggle}>Track Progress</Link></li>
            <li><Link to="/Goals" onClick={toggle}>Set Calorie Goal</Link></li>
            <li><Link to="/Settings" onClick={toggle}>Settings</Link></li>
            <li>
              <button onClick={() => { logout(); toggleMenu(); }} className={styles.menuLogoutButton}>
                Logout
              </button>
            </li>
          </ul>
        </div>
      )}
    </>
  );
};

export default DashboardHeader;
