/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  theme: {
    extend: {
      colors: {
        // SOC dark theme palette
        'soc-bg':      '#0F172A',
        'soc-card':    '#1E293B',
        'soc-border':  '#334155',
        'soc-text':    '#F1F5F9',
        'soc-muted':   '#94A3B8',
        // Severity
        'critical':    '#EF4444',
        'high':        '#F97316',
        'medium':      '#EAB308',
        'low':         '#3B82F6',
      },
    },
  },
  plugins: [],
}
