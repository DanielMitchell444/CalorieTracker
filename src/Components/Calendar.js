import React, { useState } from "react";
import styles from "../App.module.css"; // Import your CSS Module

const Calendar = () => {
  const [currentDate, setCurrentDate] = useState(new Date());

  const getDaysInMonth = (year, month) => {
    return new Date(year, month + 1, 0).getDate();
  };

  const getFirstDayOfMonth = (year, month) => {
    return new Date(year, month, 1).getDay();
  };

  const handlePreviousMonth = () => {
    setCurrentDate(
      new Date(currentDate.getFullYear(), currentDate.getMonth() - 1, 1)
    );
  };

  const handleNextMonth = () => {
    setCurrentDate(
      new Date(currentDate.getFullYear(), currentDate.getMonth() + 1, 1)
    );
  };

  const year = currentDate.getFullYear();
  const month = currentDate.getMonth();
  const daysInMonth = getDaysInMonth(year, month);
  const firstDay = getFirstDayOfMonth(year, month);

  const renderDays = () => {
    const days = [];
    // Empty cells before the first day
    for (let i = 0; i < firstDay; i++) {
      days.push(
        <div key={`empty-${i}`} className={styles.empty}></div>
      );
    }

    // Actual days
    for (let day = 1; day <= daysInMonth; day++) {
      // Add color-coded classes for specific states
      let colorClass = "";
      if (day % 5 === 0) colorClass = styles.green; // Example condition
      else if (day % 7 === 0) colorClass = styles.red; // Example condition

      days.push(
        <div key={day} className={`${styles.day} ${colorClass}`}>
          {day}
        </div>
      );
    }

    return days;
  };

  return (
    <div className={styles.calendar}>
      <div className={styles.header}>
        <button onClick={handlePreviousMonth} className={styles.navButton}>
          {"<"}
        </button>
        <span className={styles.title}>
          {currentDate.toLocaleString("default", { month: "long" })} {year}
        </span>
        <button onClick={handleNextMonth} className={styles.navButton}>
          {">"}
        </button>
      </div>
      <div className={styles.daysGrid}>{renderDays()}</div>
      <div className= {styles.bottomContainer}>
        <div className= {styles.daysContainer}>
        <h1>Days Missed</h1>
        <p>21 Days</p>
     </div>
     <div className= {styles.bottomContainer2}>
      <h1>Percent of days green</h1>
      <p>%</p>
     </div>
      </div>
    </div>
  );
};

export default Calendar;
