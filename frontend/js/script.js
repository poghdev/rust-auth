const API_URL = 'http://localhost:3000/api/v1/auth';

const messageEl = document.getElementById('authMessage');

function showMessage(text, isError = false) {
    messageEl.textContent = text;
    messageEl.classList.remove(
        'hidden', 'bg-red-50', 'text-red-600', 'bg-green-50', 'text-green-600'
    );
    messageEl.classList.add(
        isError ? 'bg-red-50' : 'bg-green-50',
        isError ? 'text-red-600' : 'text-green-600'
    );
}

async function startTokenRefreshLoop() {
    const INTERVAL_MS = 14 * 60 * 1000;

    async function refresh() {
        try {
            const res = await fetch(`${API_URL}/refresh-token`, {
                method: 'POST',
                credentials: 'include',
            });
            if (!res.ok) {
                console.warn('Session expired. Please log in again.');
                clearInterval(intervalId);
            }
        } catch (err) {
            console.error('Token refresh error:', err);
        }
    }

    const intervalId = setInterval(refresh, INTERVAL_MS);
}

document.getElementById('registerForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const username = document.getElementById('regUsername').value;
    const password = document.getElementById('regPassword').value;

    const usernameLen = username.trim().length;
    if (usernameLen < 3)  return showMessage("Username must be at least 3 characters.", true);
    if (usernameLen > 10) return showMessage("Username cannot exceed 10 characters.", true);
    if (password.length < 8) return showMessage("Password must be at least 8 characters.", true);

    try {
        const res = await fetch(`${API_URL}/register`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password }),
        });

        if (res.ok) {
            showMessage("Registered! You can now log in.");
            toggleForm();
        } else {
            showMessage("Registration failed. User may already exist.", true);
        }
    } catch (err) {
        console.error("Registration error:", err);
        showMessage("Registration failed. Connection error.", true);
    }
});

document.getElementById('loginForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const username = document.getElementById('loginUsername').value;
    const password = document.getElementById('loginPassword').value;

    if (!username || !password) return showMessage("Enter username and password.", true);

    try {
        const res = await fetch(`${API_URL}/login`, {
            method: 'POST',
            credentials: 'include',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password }),
        });

        if (res.ok) {
            showMessage("Welcome back!");
            startTokenRefreshLoop();
        } else {
            showMessage("Invalid credentials.", true);
        }
    } catch (err) {
        console.error("Login error:", err);
        showMessage("Login failed. Check server or CORS settings.", true);
    }
});