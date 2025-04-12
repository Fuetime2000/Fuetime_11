// Initialize all tooltips
document.addEventListener('DOMContentLoaded', function() {
    var tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'))
    var tooltipList = tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl)
    });

    // Auto-hide flash messages after 5 seconds
    setTimeout(function() {
        var alerts = document.querySelectorAll('.alert');
        alerts.forEach(function(alert) {
            var bsAlert = new bootstrap.Alert(alert);
            bsAlert.close();
        });
    }, 5000);

    // Handle file input change for profile photo
    var photoInput = document.getElementById('photo-upload');
    if (photoInput) {
        photoInput.addEventListener('change', function() {
            if (this.files && this.files[0]) {
                var form = this.closest('form');
                if (form) {
                    form.submit();
                }
            }
        });
    }

    // Share functionality
    var shareButtons = document.querySelectorAll('.share-btn');
    shareButtons.forEach(function(button) {
        button.addEventListener('click', function() {
            var name = this.dataset.name;
            var work = this.dataset.work;
            var location = this.dataset.location;
            var text = `Check out ${name}, a ${work} in ${location} on Fuetime!`;
            var url = window.location.href;

            if (navigator.share) {
                navigator.share({
                    title: 'Fuetime Worker Profile',
                    text: text,
                    url: url
                }).catch(console.error);
            } else {
                // Fallback to copying to clipboard
                navigator.clipboard.writeText(text + ' ' + url).then(function() {
                    alert('Link copied to clipboard!');
                }).catch(function() {
                    prompt('Copy this link:', url);
                });
            }
        });
    });
});
