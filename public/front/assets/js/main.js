        // JavaScript for the hover effect on the All Category button
        document.addEventListener('DOMContentLoaded', function() {
            const categoriesButton = document.querySelector('[data-bs-target="#categoriesOffcanvas"]');
            const offcanvasElement = document.getElementById('categoriesOffcanvas');
            const offcanvas = new bootstrap.Offcanvas(offcanvasElement);

            // if (categoriesButton) {
            //     categoriesButton.addEventListener('mouseenter', () => {
            //         // Only show on desktop/tablet views (when the button is visible)
            //         if (window.innerWidth >= 992) {
            //             offcanvas.show();
            //         }
            //     });
            // }
        });

        // JavaScript to toggle password visibility
        const togglePassword = document.querySelector('#togglePassword');
        const password = document.querySelector('#password');
        if (togglePassword && password) {
            togglePassword.addEventListener('click', function(e) {
                // toggle the type attribute
                const type = password.getAttribute('type') === 'password' ? 'text' : 'password';
                password.setAttribute('type', type);
                // toggle the icon
                this.querySelector('i').classList.toggle('bi-eye');
                this.querySelector('i').classList.toggle('bi-eye-slash');
            });
        }