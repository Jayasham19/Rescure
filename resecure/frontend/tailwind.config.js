/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        canvas: {
          base: '#0A0F1D',
          surface1: '#0F172A',
          surface2: '#111827',
          surface3: '#1E293B',
          surface4: '#273549',
        },
        cyber: {
          border: {
            subtle: '#1E293B',
            medium: '#334155',
            strong: '#475569',
            focus: '#06B6D4',
          },
          text: {
            primary: '#F8FAFC',
            secondary: '#CBD5E1',
            muted: '#94A3B8',
            disabled: '#64748B',
          },
          healthy: '#10B981',
          warning: '#F59E0B',
          danger: '#EF4444',
          cyan: '#06B6D4',
          blue: '#3B82F6',
          diagnostic: '#6366F1',
          reconstructed: '#8B5CF6',
        },
      },
      fontFamily: {
        sans: ['"Times New Roman"', 'Times', 'serif'],
        mono: ['"Times New Roman"', 'Times', 'serif'],
        serif: ['"Times New Roman"', 'Times', 'serif'],
      },
      boxShadow: {
        'cyan-glow': '0 0 16px rgba(6, 182, 212, 0.4)',
        'crimson-glow': '0 0 16px rgba(239, 68, 68, 0.4)',
        'emerald-glow': '0 0 16px rgba(16, 185, 129, 0.4)',
        'amber-glow': '0 0 16px rgba(245, 158, 11, 0.4)',
      },
    },
  },
  plugins: [],
}
