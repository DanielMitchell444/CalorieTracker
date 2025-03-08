// Import the functions you need from the SDKs you need
import { initializeApp } from "firebase/app";
import { getAnalytics } from "firebase/analytics";
import { getAuth, GoogleAuthProvider, signInWithPopup } from "firebase/auth"
// TODO: Add SDKs for Firebase products that you want to use
// https://firebase.google.com/docs/web/setup#available-libraries

// Your web app's Firebase configuration
// For Firebase JS SDK v7.20.0 and later, measurementId is optional
const firebaseConfig = {
  apiKey: "AIzaSyD82PeS3ZcnQ1pKT1N74cTRudI92hN1b_E",
  authDomain: "calorie-tra.firebaseapp.com",
  projectId: "calorie-tra",
  storageBucket: "calorie-tra.firebasestorage.app",
  messagingSenderId: "177752910209",
  appId: "1:177752910209:web:9d4f9670c98a6ff7d8e080",
  measurementId: "G-F9G6VTCV5B"
};

// Initialize Firebase
const app = initializeApp(firebaseConfig);
const analytics = getAnalytics(app);
const auth = getAuth(app);
const googleProvider = new GoogleAuthProvider();

export { auth, googleProvider, signInWithPopup };