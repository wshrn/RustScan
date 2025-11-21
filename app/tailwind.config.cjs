/** @type {import('tailwindcss').Config} */
module.exports = {
  content: ['./index.html', './src/**/*.{vue,js,ts,jsx,tsx}'],
  theme: {
    extend: {
      transitionTimingFunction: {
        apple: 'cubic-bezier(0.25, 0.1, 0.25, 1.0)',
      },
    },
  },
  plugins: [],
}
