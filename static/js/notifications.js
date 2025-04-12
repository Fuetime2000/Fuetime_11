// Initialize Socket.IO connection
let socket = io();

// Notification preferences (can be saved to localStorage)
const notificationPreferences = {
    desktop: true,
    sound: true,
    inApp: true
};

// Create notification sound
const notificationSound = new Audio('/static/sounds/notification.mp3');

// Request notification permission on load
if ("Notification" in window) {
    Notification.requestPermission();
}

// Handle connection
socket.on('connect', function() {
    if (USER_ID) {  // USER_ID will be set in base.html
        socket.emit('join', { room: `user_${USER_ID}` });
    }
});

// Handle notifications
socket.on('notification', function(data) {
    showNotification(data.message, data.type);
});

// Handle new messages
socket.on('new_message', function(data) {
    // Update unread message count in navbar
    updateUnreadCount();
    
    // Don't show notifications if we're in the chat with this sender
    if (window.location.pathname.includes('/message/') && 
        window.location.pathname.includes(data.sender_id.toString())) {
        return;
    }
    
    // Show different notifications based on preferences
    if (notificationPreferences.desktop && Notification.permission === "granted") {
        // Desktop notification
        const notification = new Notification("New Message", {
            body: `${data.sender_name}: ${data.content}`,
            icon: "/static/img/logo.png"
        });
        
        // Close the notification after 5 seconds
        setTimeout(() => notification.close(), 5000);
        
        // Focus window when notification is clicked
        notification.onclick = function() {
            window.focus();
            window.location.href = `/message/${data.sender_id}`;
        };
    }
    
    if (notificationPreferences.sound) {
        notificationSound.play().catch(e => console.log('Error playing sound:', e));
    }
    
    if (notificationPreferences.inApp) {
        showNotification(`New message from ${data.sender_name}`, 'info');
    }
});

// Show notification using Bootstrap toast
function showNotification(message, type = 'info') {
    const toastContainer = document.getElementById('toast-container');
    if (!toastContainer) return;

    const toast = document.createElement('div');
    toast.className = `toast align-items-center border-0 bg-${type}`;
    toast.setAttribute('role', 'alert');
    toast.setAttribute('aria-live', 'assertive');
    toast.setAttribute('aria-atomic', 'true');

    toast.innerHTML = `
        <div class="d-flex">
            <div class="toast-body text-white">
                ${message}
            </div>
            <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast"></button>
        </div>
    `;

    toastContainer.appendChild(toast);
    const bsToast = new bootstrap.Toast(toast);
    bsToast.show();

    // Remove toast after it's hidden
    toast.addEventListener('hidden.bs.toast', function() {
        toast.remove();
    });
}

// Update unread message count in navbar
function updateUnreadCount() {
    fetch('/api/unread_count')
        .then(response => response.json())
        .then(data => {
            const badge = document.querySelector('#message-badge');
            if (badge) {
                if (data.count > 0) {
                    badge.textContent = data.count;
                    badge.style.display = 'inline';
                    // Update page title to show unread count
                    document.title = `(${data.count}) Fuetime`;
                } else {
                    badge.style.display = 'none';
                    document.title = 'Fuetime';
                }
            }
        });
}

// Function to toggle notification preferences
function toggleNotificationPreference(type) {
    notificationPreferences[type] = !notificationPreferences[type];
    localStorage.setItem('notificationPreferences', JSON.stringify(notificationPreferences));
}

// Load notification preferences from localStorage
function loadNotificationPreferences() {
    const saved = localStorage.getItem('notificationPreferences');
    if (saved) {
        Object.assign(notificationPreferences, JSON.parse(saved));
    }
}

// Initialize preferences on load
loadNotificationPreferences();
