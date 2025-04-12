// Phone call functionality
function handleCall(phoneNumber) {
    window.location.href = `tel:${phoneNumber}`;
}

// Message functionality
function handleMessage(userId) {
    window.location.href = `/chat/${userId}`;
}

// Share functionality
function handleShare(url) {
    if (navigator.share) {
        navigator.share({
            title: 'Fuetime Worker Profile',
            text: 'Check out this worker profile on Fuetime!',
            url: url
        })
        .catch(error => console.log('Error sharing:', error));
    } else {
        // Fallback for browsers that don't support Web Share API
        const tempInput = document.createElement('input');
        document.body.appendChild(tempInput);
        tempInput.value = url;
        tempInput.select();
        document.execCommand('copy');
        document.body.removeChild(tempInput);
        alert('Profile link copied to clipboard!');
    }
}

// Close flash messages after 5 seconds
document.addEventListener('DOMContentLoaded', function() {
    setTimeout(function() {
        const alerts = document.querySelectorAll('.alert');
        alerts.forEach(alert => {
            const bsAlert = new bootstrap.Alert(alert);
            bsAlert.close();
        });
    }, 5000);
});
