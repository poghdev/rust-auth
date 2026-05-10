const API_URL = 'http://localhost:3000/api/v1/auth';

const messageEl = document.getElementById('authMessage');

function showMessage(text, isError = false) {
    messageEl.textContent = text;
    messageEl.classList.remove('hidden', 'bg-red-50', 'text-red-600', 'bg-green-50', 'text-green-600');
    
    const bgColor = isError ? 'bg-red-50' : 'bg-green-50';
    const textColor = isError ? 'text-red-600' : 'text-green-600';
    
    messageEl.classList.add(bgColor, textColor);
    messageEl.classList.remove('hidden');
}

document.getElementById('registerForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const username = document.getElementById('regUsername').value;
    const password = document.getElementById('regPassword').value;

    const usernameLen = username.trim().length;
    if (usernameLen < 3) {
        showMessage("Username must be at least 3 characters long.", true);
        return;
    }
    if (usernameLen > 10) {
        showMessage("Username cannot be longer than 10 characters.", true);
        return;
    }
    if (password.length < 8) {
        showMessage("Password must be at least 8 characters long.", true);
        return;
    }

    try {
        const response = await fetch(`${API_URL}/register`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password })
        });

        if (response.ok) {
            showMessage("Registration successful! You can now log in.");
            toggleForm();
        } else {
            showMessage("Registration failed. User may already exist.", true);
        }
    } catch (err) {
        console.error("Registration error:", err);
    }
});

document.getElementById('loginForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const username = document.getElementById('loginUsername').value;
    const password = document.getElementById('loginPassword').value;

    if (!username || !password) {
        showMessage("Please enter both username and password.", true);
        return;
    }

    try {
        const response = await fetch(`${API_URL}/login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password })
        });

        if (response.ok) {
            const data = await response.json();
            console.log("Auth success");
            showMessage("Welcome back!");
        } else {
            showMessage("Invalid credentials.", true);
        }
    } catch (err) {
        console.error("Fetch error:", err);
    }
});