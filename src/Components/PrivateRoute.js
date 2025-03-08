import { Navigate } from 'react-router-dom';

const PrivateRoute = ({ children, isAuthenticated }) => {
  // Check if the user is authenticated
  if (!isAuthenticated) {
    return <Navigate to="/" />;  // Redirect to login if not authenticated
  }

  return children;  // If authenticated, render the children components
};

export default PrivateRoute;