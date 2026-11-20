function copyToClipboard(text, button) {
    navigator.clipboard.writeText(text).then(function() {
        // Change button text and icon
        const btnText = button.querySelector('.btn-text');
        const originalText = btnText.textContent;
        btnText.textContent = 'Copied!';
        button.classList.add('btn-success');
        button.classList.remove('btn-outline-secondary');

        // Reset after 2 seconds
        setTimeout(function() {
            btnText.textContent = originalText;
            button.classList.remove('btn-success');
            button.classList.add('btn-outline-secondary');
        }, 2000);
    }).catch(function(err) {
        console.error('Failed to copy:', err);
        alert('Failed to copy to clipboard');
    });
}
