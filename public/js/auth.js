// Check if user is authenticated
function isAuthenticated() {
    const token = localStorage.getItem('token');
    return !!token;
}

// Get authentication token
function getAuthToken() {
    return localStorage.getItem('token');
}

// Get current user
function getCurrentUser() {
    const userStr = localStorage.getItem('user');
    return userStr ? JSON.parse(userStr) : null;
}

// Logout user
function logout() {
    localStorage.removeItem('token');
    localStorage.removeItem('user');
    window.location.href = 'login.html';
}

// Add auth header to fetch requests
function addAuthHeader(headers = {}) {
    const token = getAuthToken();
    if (token) {
        return {
            ...headers,
            'Authorization': `Bearer ${token}`
        };
    }
    return headers;
}

// Redirect to login if not authenticated
function requireAuth() {
    if (!isAuthenticated()) {
        window.location.href = 'login.html';
    }
}

// Check authentication on page load
document.addEventListener('DOMContentLoaded', () => {
    // If on login or signup page and already authenticated, redirect to dashboard
    if ((window.location.pathname.includes('login.html') ||
        window.location.pathname.includes('signup.html')) &&
        isAuthenticated()) {
        window.location.href = 'dashboard.html';
    }

    // If on protected page and not authenticated, redirect to login
    if (window.location.pathname.includes('dashboard.html') && !isAuthenticated()) {
        window.location.href = 'login.html';
    }
}); 