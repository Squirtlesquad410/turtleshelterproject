/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    './views/**/*.ejs',  // Make sure this points to your EJS files
    './public/**/*.{html,js}',  // Include other files that might contain Tailwind classes
  ],
  theme: {
    extend: {},
  },
  plugins: [],
}
