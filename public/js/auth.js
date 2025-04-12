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

// Update user avatar based on profile data
function updateUserAvatar() {
    const user = getCurrentUser();
    if (user && user.picture) {
        // User has a profile picture (from Google)
        const avatarImage = document.getElementById('user-avatar-image');
        const avatarLetter = document.getElementById('user-avatar-letter');
        const avatarContainer = document.getElementById('user-avatar-container');

        if (avatarImage && avatarLetter && avatarContainer) {
            avatarImage.src = user.picture;
            avatarImage.classList.remove('d-none');
            avatarLetter.classList.add('d-none');
        }
    } else if (user && user.name) {
        // User doesn't have a picture, display first letter
        const avatarLetter = document.getElementById('user-avatar-letter');
        if (avatarLetter) {
            avatarLetter.textContent = user.name.charAt(0).toUpperCase();
        }
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

    // If on dashboard, display user info
    if (window.location.pathname.includes('dashboard.html') && isAuthenticated()) {
        const user = getCurrentUser();
        if (user) {
            // Update user name display
            const userNameElement = document.getElementById('user-name');
            if (userNameElement) {
                userNameElement.textContent = user.name;
            }

            // Update avatar
            updateUserAvatar();
        }
    }
}); 