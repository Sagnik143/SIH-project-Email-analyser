/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        cyber: {
          dark: '#070a12',
          card: '#0d1424',
          border: 'rgba(56, 189, 248, 0.15)',
          cyan: '#00f0ff',
          neon: '#00ffcc',
        }
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', 'sans-serif'],
        mono: ['JetBrains Mono', 'monospace'],
        display: ['Chakra Petch', 'sans-serif'],
      }
    },
  },
  plugins: [],
}
