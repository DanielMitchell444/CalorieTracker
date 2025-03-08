import React from 'react';
import styles from '../App.module.css';

const DaysOfWeek = () => {
  const days = ['M', 'T', 'W', 'Th', 'F', 'Sa', 'Su'];

  return (
    <div className={styles.daysContainer}>
      {days.map((day) => (
        <button key={day} className={styles.dayButton}>
          {day}
        </button>
      ))}
    </div>
  );
};

export default DaysOfWeek;