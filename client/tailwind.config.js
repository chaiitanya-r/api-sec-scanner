/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,jsx}"
  ],
  darkMode: "class",
  theme: {
    extend: {
      colors: {
        darkBg: "#0a0d14",
        darkCard: "#111622",
        darkBorder: "#1e2638"
      }
    }
  },
  plugins: []
};
