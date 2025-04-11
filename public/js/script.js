document.addEventListener('DOMContentLoaded', function () {
    // Initialize message form
    const messageForm = document.getElementById('messageForm');
    if (messageForm) {
        messageForm.addEventListener('submit', function (e) {
            e.preventDefault();

            try {
                // Clear previous results
                clearMessageResults();

                // Get form values
                const phoneNumbers = document.getElementById('phoneNumbers').value.split('\n').filter(num => num.trim());
                const message = document.getElementById('message').value;
                const selectedSession = document.querySelector('input[name="session"]:checked');

                if (!selectedSession) {
                    displayMessageResult('N/A', false, 'Please select a session');
                    return;
                }

                if (phoneNumbers.length === 0) {
                    displayMessageResult('N/A', false, 'Please enter at least one phone number');
                    return;
                }

                if (!message.trim()) {
                    displayMessageResult('N/A', false, 'Please enter a message');
                    return;
                }

                // Send message for each phone number
                phoneNumbers.forEach((number, index) => {
                    // Simulate sending message (replace with actual API call)
                    setTimeout(() => {
                        try {
                            const success = Math.random() > 0.3; // 70% success rate for demo
                            displayMessageResult(number, success, success ? 'Message sent successfully' : 'Failed to send message');
                        } catch (error) {
                            console.error('Error processing message for number ' + number + ':', error);
                        }
                    }, index * 500); // Stagger the results
                });
            } catch (error) {
                console.error('Error processing form submission:', error);
            }
        });
    }
});

function displayMessageResult(number, success, message) {
    try {
        const messageResults = document.querySelector('.message-results');
        if (!messageResults) {
            console.error('Message results container not found');
            return;
        }

        const resultItem = document.createElement('div');
        resultItem.className = 'message-result-item';

        const icon = document.createElement('i');
        icon.className = success ? 'fas fa-check-circle success-icon' : 'fas fa-times-circle error-icon';

        const resultNumber = document.createElement('span');
        resultNumber.className = 'message-result-number';
        resultNumber.textContent = number;

        const resultMessage = document.createElement('span');
        resultMessage.className = 'message-result-message';
        resultMessage.textContent = message;

        resultItem.appendChild(icon);
        resultItem.appendChild(resultNumber);
        resultItem.appendChild(resultMessage);

        messageResults.appendChild(resultItem);
        messageResults.scrollTop = messageResults.scrollHeight;
    } catch (error) {
        console.error('Error displaying message result:', error);
    }
}

function clearMessageResults() {
    try {
        const messageResults = document.querySelector('.message-results');
        if (!messageResults) {
            console.error('Message results container not found');
            return;
        }
        messageResults.innerHTML = '';
    } catch (error) {
        console.error('Error clearing message results:', error);
    }
} 