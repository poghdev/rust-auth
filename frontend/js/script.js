const API_URL = 'http://localhost:3000';

document.getElementById('registerForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const username = document.getElementById('regUsername').value;
    const password = document.getElementById('regPassword').value;

    try {
        const response = await fetch(`${API_URL}/register`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password })
        });

        if (response.ok) {
            alert("Registration successful! You can now log in.");
            toggleForm();
        } else {
            alert("Registration failed. User may already exist.");
        }
    } catch (err) {
        console.error("Registration error:", err);
    }
});

document.getElementById('loginForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const username = document.getElementById('loginUsername').value;
    const password = document.getElementById('loginPassword').value;

    try {
        const response = await fetch(`${API_URL}/login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password })
        });

        if (response.ok) {
            const data = await response.json();
            localStorage.setItem('token', data.token);
            console.log("Auth success");
            alert("Welcome back!");
        } else {
            alert("Invalid credentials.");
        }
    } catch (err) {
        console.error("Fetch error:", err);
    }
});