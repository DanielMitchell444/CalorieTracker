import React from "react";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { faBullseye } from "@fortawesome/free-solid-svg-icons";
import styles from '../App.module.css'
import { faRunning } from "@fortawesome/free-solid-svg-icons";
import { faDumbbell } from "@fortawesome/free-solid-svg-icons";
import { faHeartbeat } from "@fortawesome/free-solid-svg-icons";
const Setup = ({handleClick, steps, goals}) => {
 return (
<div className= {styles.setupContainer2}>
<div className= {styles.setupBody2}>

{steps === 1 && (
<>
 <div className= {styles.setupHeader2}>
    <h1>Finish Setup</h1>
    <p>Finish your acount Setup</p>
 </div>

 <div className= {styles.cardsContainer}>
      <div className= {styles.cards}>
        <div className= {styles.cardWrapper}>
        <h1>Lose Weight</h1>
        <p>I want this app to help me lose weight!</p>
        <FontAwesomeIcon

        icon = {faRunning}
        className= {styles.icon}

        />

<button className= {styles.selectGoals}
onClick={() => handleClick({goal: 'lose weight'})}
>Select Goal</button>
        </div>
        </div>
</div>

<div className= {styles.cardsContainer}>
      <div className= {styles.cards}>
        <div className= {styles.cardWrapper}>
        <h1>Gain Weight</h1>
        <p>I want this app to help me gain weight!</p>
        <FontAwesomeIcon

        icon = {faDumbbell}
        className= {styles.icon}

        />

<button className= {styles.selectGoals}
onClick={() => handleClick({goal: 'gain weight'})}
>Select Goal</button>
        </div>
        </div>
</div>

<div className= {styles.cardsContainer}>
      <div className= {styles.cards}>
        <div className= {styles.cardWrapper}>
        <h1>Maintain Weight</h1>
        <p>I want this app to help me maintain weight!</p>
        <FontAwesomeIcon

        icon = {faHeartbeat}
        className= {styles.icon}

        />
        <button className= {styles.selectGoals}
        onClick = {() => handleClick({goal: 'maintain weight'})}
        >Select Goal</button>
        </div>
        </div>
</div>
</>
)
}

{
 steps === 2 && goals.goals === "lose weight" && ( 
<>
<div className= {styles.loseWeightContainer}>
<h1>Hi</h1>
</div>
</>
 )       
}

{
 steps === 2 && goals.goals === "gain weight" && ( 
<>
<div className="">
<h1>Bye</h1>
</div>
</>
 )       
}
</div>
</div>
 )
}

export default Setup