document.addEventListener('DOMContentLoaded', () => {
    // DOM Elements
    const loginForm = document.getElementById('loginForm');
    const signupForm = document.getElementById('signupForm');
    const loginBtn = document.getElementById('loginBtn');
    const signupBtn = document.getElementById('signupBtn');

    // Show/Hide Forms
    const showLogin = () => {
        loginForm.classList.remove('hidden');
        signupForm.classList.add('hidden');
        loginBtn.classList.add('btn-primary');
        signupBtn.classList.remove('btn-primary');
    };

    const showSignup = () => {
        loginForm.classList.add('hidden');
        signupForm.classList.remove('hidden');
        loginBtn.classList.remove('btn-primary');
        signupBtn.classList.add('btn-primary');
    };

    // Event Listeners
    loginBtn.addEventListener('click', showLogin);
    signupBtn.addEventListener('click', showSignup);

    // Handle Login
    document.getElementById('login').addEventListener('submit', async (e) => {
        e.preventDefault();
        const email = document.getElementById('loginEmail').value;
        const password = document.getElementById('loginPassword').value;

        try {
            const response = await fetch('/api/login', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ email, password }),
            });

            const data = await response.json();

            if (response.ok) {
                localStorage.setItem('token', data.token);
                localStorage.setItem('userType', data.user_type);
                window.location.href = data.user_type === 'job_seeker' ? '/seeker-profile.html' : '/employer-profile.html';
            } else {
                alert(data.error || 'Login failed');
            }
        } catch (error) {
            console.error('Error:', error);
            alert('An error occurred during login');
        }
    });

    // Handle Signup
    document.getElementById('signup').addEventListener('submit', async (e) => {
        e.preventDefault();
        const firstName = document.getElementById('firstName').value;
        const lastName = document.getElementById('lastName').value;
        const email = document.getElementById('signupEmail').value;
        const phone = document.getElementById('phone').value;
        const password = document.getElementById('signupPassword').value;
        const confirmPassword = document.getElementById('confirmPassword').value;

        if (password !== confirmPassword) {
            alert('Passwords do not match');
            return;
        }

        try {
            const response = await fetch('/api/register', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    first_name: firstName,
                    last_name: lastName,
                    email,
                    phone,
                    password,
                    user_type: 'job_seeker' // Default to job seeker
                }),
            });

            const data = await response.json();

            if (response.ok) {
                alert('Registration successful! Please log in.');
                showLogin();
            } else {
                alert(data.error || 'Registration failed');
            }
        } catch (error) {
            console.error('Error:', error);
            alert('An error occurred during registration');
        }
    });

    // Show signup form by default
    showSignup();
}); 