import React, { useState } from "react";
import axios from "axios";

const RecipeAutocomplete = () => {
  const [query, setQuery] = useState("");
  const [suggestions, setSuggestions] = useState([]);

  const fetchSuggestions = async () => {
    const API_KEY = "YOUR_SPOONACULAR_API_KEY"; // Replace with your API key
    const url = `https://api.spoonacular.com/recipes/autocomplete?apiKey=${API_KEY}&query=${query}&number=10`;

    try {
      const response = await axios.get(url);
      setSuggestions(response.data);
    } catch (error) {
      console.error("Error fetching suggestions:", error);
    }
  };

  return (
    <div>
      <h1>Recipe Autocomplete</h1>
      <input
        type="text"
        placeholder="Search for recipes..."
        value={query}
        onChange={(e) => setQuery(e.target.value)}
      />
      <button onClick={fetchSuggestions}>Search</button>
      <ul>
        {suggestions.map((suggestion) => (
          <li key={suggestion.id}>{suggestion.title}</li>
        ))}
      </ul>
    </div>
  );
};

export default RecipeAutocomplete;