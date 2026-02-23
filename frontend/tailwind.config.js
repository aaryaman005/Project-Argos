/** @type {import('tailwindcss').Config} */
export default {
    content: [
        "./index.html",
        "./src/**/*.{js,ts,jsx,tsx}",
    ],
    theme: {
        extend: {
            colors: {
                brand: {
                    50: '#f0f7ff',
                    100: '#e0effe',
                    200: '#bae0fd',
                    300: '#7cc7fb',
                    400: '#38aaf7',
                    500: '#0e8ce9',
                    600: '#026ec7',
                    700: '#0358a1',
                    800: '#074b85',
                    900: '#0c406e',
                    950: '#082949',
                },
            },
        },
    },
    plugins: [],
}
