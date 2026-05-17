const API = 'http://localhost:3000/api/v1/auth';

const messageEl = document.getElementById('authMessage');

function showMessage(text, isError = false) {
    messageEl.textContent = text;
    messageEl.classList.remove('hidden', 'bg-red-50', 'text-red-600', 'bg-green-50', 'text-green-600');
    messageEl.classList.add(
        isError ? 'bg-red-50'    : 'bg-green-50',
        isError ? 'text-red-600' : 'text-green-600',
    );
}

// ── Token refresh loop ────────────────────────────────────────────────────────

let refreshIntervalId = null;

function startTokenRefreshLoop() {
    if (refreshIntervalId !== null) return;

    const INTERVAL = 14 * 60 * 1000;

    refreshIntervalId = setInterval(async () => {
        try {
            const res = await fetch(`${API}/refresh-token`, {
                method: 'POST',
                credentials: 'include',
            });
            if (!res.ok) {
                stopTokenRefreshLoop();
                showMessage('Session expired. Please log in again.', true);
            }
        } catch {
            stopTokenRefreshLoop();
            showMessage('Connection lost. Please log in again.', true);
        }
    }, INTERVAL);
}

function stopTokenRefreshLoop() {
    if (refreshIntervalId !== null) {
        clearInterval(refreshIntervalId);
        refreshIntervalId = null;
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function setLoading(btn, isLoading) {
    btn.disabled = isLoading;
    btn.style.opacity = isLoading ? '0.6' : '1';
    btn.style.cursor  = isLoading ? 'not-allowed' : '';
}

// ── Register ──────────────────────────────────────────────────────────────────

document.getElementById('registerForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const username = document.getElementById('regUsername').value.trim();
    const password = document.getElementById('regPassword').value;
    const btn      = e.target.querySelector('button[type="submit"]');

    if (username.length < 3)  return showMessage('Username must be at least 3 characters.', true);
    if (username.length > 10) return showMessage('Username cannot exceed 10 characters.', true);
    if (password.length < 8)  return showMessage('Password must be at least 8 characters.', true);

    setLoading(btn, true);
    try {
        const res = await fetch(`${API}/register`, {
            method:  'POST',
            headers: { 'Content-Type': 'application/json' },
            body:    JSON.stringify({ username, password }),
        });

        if (res.ok) {
            showMessage('Registered! You can now log in.');
            e.target.reset();
            toggleForm();
        } else if (res.status === 409) {
            showMessage('Username already taken.', true);
        } else {
            showMessage('Registration failed.', true);
        }
    } catch {
        showMessage('Connection error.', true);
    } finally {
        setLoading(btn, false);
    }
});

// ── Login ─────────────────────────────────────────────────────────────────────

document.getElementById('loginForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const username = document.getElementById('loginUsername').value.trim();
    const password = document.getElementById('loginPassword').value;
    const btn      = e.target.querySelector('button[type="submit"]');

    if (!username || !password) return showMessage('Enter username and password.', true);

    setLoading(btn, true);
    try {
        const res = await fetch(`${API}/login`, {
            method:      'POST',
            credentials: 'include',
            headers:     { 'Content-Type': 'application/json' },
            body:        JSON.stringify({ username, password }),
        });

        if (res.ok) {
            showMessage(`Welcome, ${username}!`);
            e.target.reset();
            startTokenRefreshLoop();
        } else if (res.status === 401) {
            showMessage('Invalid credentials.', true);
        } else {
            showMessage('Login failed. Try again.', true);
        }
    } catch {
        showMessage('Connection error.', true);
    } finally {
        setLoading(btn, false);
    }
});

// ── Logout ────────────────────────────────────────────────────────────────────

async function logout() {
    stopTokenRefreshLoop();
    try {
        await fetch(`${API}/logout`, {
            method:      'POST',
            credentials: 'include',
        });
    } catch {
        // Куки почистятся на сервере при следующем запросе
    }
    showMessage('Logged out.');
}