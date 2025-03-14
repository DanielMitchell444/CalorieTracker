import React from "react";
import styles from '../App.module.css';
const ProgressBar = ({ progress }) => {

  return (
    <div className={styles.progressBarContainer}>
      <div
        className={styles.progressBar}
        style={{ width: `${progress}%` }}
      ></div>
    </div>
  );
};

export default ProgressBar;