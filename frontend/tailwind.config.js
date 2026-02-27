/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      fontFamily: {
        sans: ['Inter', 'system-ui', 'sans-serif'],
        mono: ['JetBrains Mono', 'Fira Code', 'monospace'],
      },
      colors: {
        surface: {
          DEFAULT: '#000000',
          50: '#0a0a0a',
          100: '#111111',
          200: '#1a1a1a',
          300: '#222222',
          400: '#2a2a2a',
        },
        risk: {
          critical: '#ef4444',
          high: '#f97316',
          medium: '#eab308',
          low: '#3b82f6',
          info: '#6b7280',
        },
        accent: {
          blue: '#3b82f6',
          green: '#22c55e',
          purple: '#a855f7',
          cyan: '#06b6d4',
        },
      },
      backdropBlur: {
        '3xl': '64px',
        '4xl': '80px',
      },
      animation: {
        'pulse-slow': 'pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'glow': 'glow 2s ease-in-out infinite alternate',
      },
      keyframes: {
        glow: {
          '0%': { boxShadow: '0 0 5px rgba(59, 130, 246, 0.3)' },
          '100%': { boxShadow: '0 0 20px rgba(59, 130, 246, 0.6)' },
        },
      },
    },
  },
  plugins: [],
}
