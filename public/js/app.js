const socket = io();
const sessionsContainer = document.getElementById('sessionsContainer');
const sessionRadioGroup = document.getElementById('sessionRadioGroup');
const createSessionBtn = document.getElementById('createSession');
const createSessionEmptyBtn = document.getElementById('createSessionEmpty');
const createSessionEmptyRadioBtn = document.getElementById('createSessionEmptyRadio');
const messageForm = document.getElementById('messageForm');
const loadingOverlay = document.getElementById('loadingOverlay');
const emptySessions = document.getElementById('empty-sessions');
const emptySessionsRadio = document.getElementById('empty-sessions-radio');
const sessionCount = document.getElementById('session-count');
const pageTitle = document.getElementById('page-title');

// Store active sessions
const activeSessions = new Map();

// Show loading overlay
function showLoading(message = 'Loading...') {
    loadingOverlay.querySelector('p').textContent = message;
    loadingOverlay.classList.add('active');
}

// Hide loading overlay
function hideLoading() {
    loadingOverlay.classList.remove('active');
}

// Show toast notification
function showToast(message, type = 'success') {
    const toastContainer = document.querySelector('.toast-container');
    const toastId = 'toast-' + Date.now();

    const toast = document.createElement('div');
    toast.className = `toast ${type === 'success' ? 'bg-success' : 'bg-danger'} text-white`;
    toast.id = toastId;
    toast.setAttribute('role', 'alert');
    toast.setAttribute('aria-live', 'assertive');
    toast.setAttribute('aria-atomic', 'true');

    toast.innerHTML = `
        <div class="toast-header">
            <i class="fas ${type === 'success' ? 'fa-check-circle' : 'fa-exclamation-circle'} me-2"></i>
            <strong class="me-auto">${type === 'success' ? 'Success' : 'Error'}</strong>
            <button type="button" class="btn-close" data-bs-dismiss="toast" aria-label="Close"></button>
        </div>
        <div class="toast-body">
            ${message}
        </div>
    `;

    toastContainer.appendChild(toast);

    const bsToast = new bootstrap.Toast(toast, {
        autohide: true,
        delay: 5000
    });

    bsToast.show();

    // Remove toast after it's hidden
    toast.addEventListener('hidden.bs.toast', () => {
        toast.remove();
    });
}

// Update session count
function updateSessionCount() {
    const count = activeSessions.size;
    sessionCount.textContent = count;

    if (count === 0) {
        emptySessions.style.display = 'block';
        emptySessionsRadio.style.display = 'block';
    } else {
        emptySessions.style.display = 'none';
        emptySessionsRadio.style.display = 'none';
    }
}

// Create new session
async function createNewSession() {
    showLoading('Creating new session...');

    try {
        const response = await fetch('/api/create-session', {
            method: 'POST'
        });
        const data = await response.json();
        createSessionCard(data.sessionId);
        showToast('New session created successfully');
    } catch (error) {
        console.error('Error creating session:', error);
        showToast('Failed to create session: ' + error.message, 'error');
    } finally {
        hideLoading();
    }
}

// Event listeners for create session buttons
createSessionBtn.addEventListener('click', createNewSession);
createSessionEmptyBtn.addEventListener('click', createNewSession);
createSessionEmptyRadioBtn.addEventListener('click', createNewSession);

// Create session card
function createSessionCard(sessionId, sessionStatus = null) {
    const card = document.createElement('div');
    card.className = 'col-md-4 animate__animated animate__fadeIn';

    // Determine initial status and phone number
    let initialStatus = 'connecting';
    let initialPhoneNumber = null;
    let showQrLoading = true;

    if (sessionStatus) {
        initialStatus = sessionStatus.status;
        initialPhoneNumber = sessionStatus.phoneNumber;
        showQrLoading = false; // Don't show QR loading if session is already connected
    }

    card.innerHTML = `
        <div class="card session-card">
            <div class="card-header d-flex justify-content-between align-items-center">
                <h5 class="mb-0"># ${sessionId}</h5>
                <div class="session-actions">
                    <button class="btn btn-sm btn-outline-danger delete-session" data-session-id="${sessionId}">
                        <i class="fas fa-trash"></i>
                    </button>
                </div>
            </div>
            <div class="card-body">
                <div class="qr-container" style="display: ${initialStatus === 'connected' ? 'none' : 'block'}">
                    <div class="qr-loading" style="display: ${showQrLoading ? 'block' : 'none'}">
                        <div class="spinner-border text-primary" role="status">
                            <span class="visually-hidden">Loading...</span>
                        </div>
                        <p class="mt-2">Generating QR Code...</p>
                    </div>
                    <img id="qr-${sessionId}" src="" alt="QR Code" style="display: ${showQrLoading ? 'none' : 'block'}">
                </div>
                <div class="session-status ${initialStatus}" id="status-${sessionId}">
                    <i class="fas ${initialStatus === 'connected' ? 'fa-check-circle' : initialStatus === 'disconnected' ? 'fa-times-circle' : 'fa-spinner fa-spin'} me-2"></i>
                    ${initialStatus.charAt(0).toUpperCase() + initialStatus.slice(1)}
                </div>
                <div class="phone-number" id="phone-${sessionId}">
                    ${initialPhoneNumber ? `<i class="fas fa-phone me-2"></i>${initialPhoneNumber}` : ''}
                </div>
            </div>
        </div>
    `;
    sessionsContainer.appendChild(card);

    // Add to session radio group
    const radioItem = document.createElement('div');
    radioItem.className = 'session-radio-item animate__animated animate__fadeIn';
    radioItem.innerHTML = `
        <input type="radio" name="session" id="radio-${sessionId}" class="session-radio-input" value="${sessionId}" ${activeSessions.size === 1 ? 'checked' : ''}>
        <label for="radio-${sessionId}" class="session-radio-label">
            <div class="session-radio-icon">
                <i class="fas fa-user"></i>
            </div>
            <div class="session-radio-info">
                <div class="session-radio-title">#${sessionId}</div>
                <div class="session-radio-phone" id="radio-phone-${sessionId}">${initialPhoneNumber || 'Connecting...'}</div>
            </div>
        </label>
    `;
    sessionRadioGroup.appendChild(radioItem);

    // Store session
    activeSessions.set(sessionId, {
        status: initialStatus,
        phoneNumber: initialPhoneNumber
    });

    // Update session count
    updateSessionCount();

    // Socket listeners
    socket.on(`qr-${sessionId}`, (qrCode) => {
        const qrImg = document.getElementById(`qr-${sessionId}`);
        const qrLoading = qrImg.previousElementSibling;

        qrImg.src = qrCode;
        qrImg.style.display = 'block';
        qrLoading.style.display = 'none';

        // Add pulse animation to QR code
        qrImg.classList.add('pulse');
    });

    socket.on(`session-${sessionId}-status`, (status) => {
        const statusElement = document.getElementById(`status-${sessionId}`);
        const qrContainer = statusElement.parentElement.querySelector('.qr-container');
        let statusIcon = '';

        switch (status) {
            case 'connected':
                statusIcon = '<i class="fas fa-check-circle me-2"></i>';
                // Hide QR container when connected
                qrContainer.style.display = 'none';
                break;
            case 'disconnected':
                statusIcon = '<i class="fas fa-times-circle me-2"></i>';
                // Show QR container when disconnected
                qrContainer.style.display = 'block';
                break;
            case 'connecting':
                statusIcon = '<i class="fas fa-spinner fa-spin me-2"></i>';
                // Show QR container when connecting
                qrContainer.style.display = 'block';
                break;
        }

        statusElement.innerHTML = `${statusIcon}${status.charAt(0).toUpperCase() + status.slice(1)}`;
        statusElement.className = `session-status ${status}`;

        const session = activeSessions.get(sessionId);
        session.status = status;

        // Update radio button
        const radioPhone = document.getElementById(`radio-phone-${sessionId}`);
        if (radioPhone) {
            radioPhone.textContent = session.phoneNumber || 'Connecting...';
        }

        // Show toast for status changes
        if (status === 'connected') {
            showToast(`Session ${sessionId} connected successfully`);
        } else if (status === 'disconnected') {
            showToast(`Session ${sessionId} disconnected`, 'error');
        }
    });

    socket.on(`session-${sessionId}-phone`, (phoneNumber) => {
        const phoneElement = document.getElementById(`phone-${sessionId}`);
        phoneElement.innerHTML = `<i class="fas fa-phone me-2"></i>${phoneNumber}`;

        const session = activeSessions.get(sessionId);
        session.phoneNumber = phoneNumber;

        // Update radio button
        const radioPhone = document.getElementById(`radio-phone-${sessionId}`);
        if (radioPhone) {
            radioPhone.textContent = phoneNumber;
        }
    });

    // Add delete session functionality
    const deleteBtn = card.querySelector('.delete-session');
    deleteBtn.addEventListener('click', async () => {
        if (confirm(`Are you sure you want to delete session ${sessionId}?`)) {
            showLoading('Deleting session...');

            try {
                const response = await fetch(`/api/delete-session/${sessionId}`, {
                    method: 'DELETE'
                });

                if (response.ok) {
                    // Remove from DOM with animation
                    card.classList.remove('animate__fadeIn');
                    card.classList.add('animate__fadeOut');

                    // Remove radio button
                    const radioItem = document.querySelector(`#radio-${sessionId}`).closest('.session-radio-item');
                    radioItem.classList.remove('animate__fadeIn');
                    radioItem.classList.add('animate__fadeOut');

                    setTimeout(() => {
                        card.remove();
                        radioItem.remove();

                        // Remove from active sessions
                        activeSessions.delete(sessionId);

                        // Update session count
                        updateSessionCount();

                        showToast(`Session ${sessionId} deleted successfully`);
                    }, 500);
                } else {
                    showToast('Failed to delete session', 'error');
                }
            } catch (error) {
                console.error('Error deleting session:', error);
                showToast('Error deleting session: ' + error.message, 'error');
            } finally {
                hideLoading();
            }
        }
    });
}

// Message form handling
messageForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const selectedSession = document.querySelector('input[name="session"]:checked');
    const sessionId = selectedSession ? selectedSession.value : null;
    const numbers = document.getElementById('phoneNumbers').value;
    const message = document.getElementById('message').value;

    if (!sessionId || !numbers || !message) {
        showToast('Please fill in all fields', 'error');
        return;
    }

    showLoading('Sending messages...');

    try {
        const response = await fetch('/api/send-message', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                sessionId,
                numbers,
                message
            })
        });

        const data = await response.json();

        if (data.success) {
            // Show message results
            const resultsCard = document.querySelector('.message-results-card');
            const resultsContainer = document.querySelector('.message-results');

            if (resultsCard && resultsContainer) {
                resultsContainer.innerHTML = '';
                resultsCard.style.display = 'block';

                // Add each result
                data.results.forEach(result => {
                    const resultItem = document.createElement('div');
                    resultItem.className = `message-result-item ${result.success ? 'success' : 'error'}`;
                    resultItem.innerHTML = `
                        <i class="fas ${result.success ? 'fa-check-circle' : 'fa-exclamation-circle'}"></i>
                        <div class="message-result-details">
                            <div class="message-result-number">${result.number}</div>
                            <div class="message-result-message">${result.success ? 'Message sent successfully' : result.error}</div>
                        </div>
                    `;
                    resultsContainer.appendChild(resultItem);
                });
            } else {
                console.error('Message results container not found');
                showToast('Messages sent successfully, but could not display results', 'success');
            }

            // Clear form
            document.getElementById('phoneNumbers').value = '';
            document.getElementById('message').value = '';

            showToast('Messages sent successfully');
        } else {
            showToast(data.error || 'Failed to send messages', 'error');
        }
    } catch (error) {
        console.error('Error sending messages:', error);
        showToast('Failed to send messages: ' + error.message, 'error');
    } finally {
        hideLoading();
    }
});

// Handle sidebar navigation
document.querySelectorAll('.sidebar-menu a').forEach(link => {
    link.addEventListener('click', (e) => {
        e.preventDefault();

        // Update active link
        document.querySelectorAll('.sidebar-menu a').forEach(l => l.classList.remove('active'));
        link.classList.add('active');

        // Update active section
        const sectionId = link.getAttribute('data-section');
        document.querySelectorAll('.content-section').forEach(section => {
            section.classList.remove('active');
        });
        document.getElementById(`${sectionId}-section`).classList.add('active');

        // Update page title
        pageTitle.textContent = link.querySelector('span').textContent;
    });
});

// Check for existing sessions when the page loads
async function checkExistingSessions() {
    showLoading('Loading sessions...');

    try {
        console.log('Checking for existing sessions...');
        const response = await fetch('/api/check-sessions');
        const data = await response.json();
        console.log('Existing sessions:', data);

        if (data.sessions && data.sessions.length > 0) {
            // Get current session statuses
            const statusResponse = await fetch('/api/session-statuses');
            const statusData = await statusResponse.json();
            console.log('Session statuses:', statusData);

            data.sessions.forEach(session => {
                // Use sessionId instead of id
                createSessionCard(session.sessionId, {
                    status: session.status,
                    phoneNumber: session.phoneNumber
                });
            });
        }
    } catch (error) {
        console.error('Error checking existing sessions:', error);
        showToast('Error loading sessions: ' + error.message, 'error');
    } finally {
        hideLoading();
    }
}

// Call the function when the page loads
document.addEventListener('DOMContentLoaded', checkExistingSessions);

// Mobile sidebar toggle functionality
function toggleMobileSidebar() {
    const sidebar = document.querySelector('.api-sidebar');
    sidebar.classList.toggle('expanded');
}

// Add click event to sidebar header for mobile
document.querySelector('.sidebar-header').addEventListener('click', function () {
    if (window.innerWidth <= 768) {
        toggleMobileSidebar();
    }
});

// Close sidebar when clicking outside on mobile
document.addEventListener('click', function (event) {
    const sidebar = document.querySelector('.api-sidebar');
    const sidebarHeader = document.querySelector('.sidebar-header');

    if (window.innerWidth <= 768 &&
        sidebar.classList.contains('expanded') &&
        !sidebar.contains(event.target) &&
        !sidebarHeader.contains(event.target)) {
        sidebar.classList.remove('expanded');
    }
});

// Handle window resize
window.addEventListener('resize', function () {
    const sidebar = document.querySelector('.api-sidebar');
    if (window.innerWidth > 768) {
        sidebar.classList.remove('expanded');
    }
}); 