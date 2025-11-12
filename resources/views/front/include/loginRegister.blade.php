<div class="offcanvas offcanvas-end" tabindex="-1" id="signInOffcanvas" aria-labelledby="signInOffcanvasLabel">
    <div class="offcanvas-header">
        <h5 class="offcanvas-title" id="signInOffcanvasLabel">Sign in</h5>
        <button type="button" class="btn-close text-reset" data-bs-dismiss="offcanvas" aria-label="Close"></button>
    </div>
    <div class="offcanvas-body" style="overflow-y: auto; padding-bottom: 80px;">
        {{-- General Error Message Area --}}
        <div id="auth-error-message" class="alert alert-danger" style="display: none;"></div>

        {{-- Login Form --}}
        <form id="loginForm" novalidate>
             @csrf
            <div class="mb-3">
                <label for="loginEmail" class="form-label">Email or Phone <span class="text-danger">*</span></label>
                <input type="text" class="form-control" name="email" id="loginEmail" required>
                <div class="invalid-feedback"></div>
            </div>
            <div class="mb-3">
                <label for="loginPassword" class="form-label">Password <span class="text-danger">*</span></label>
                <div class="input-group">
                    <input type="password" class="form-control" autocomplete="new-password" 
       readonly 
       onfocus="this.removeAttribute('readonly');" name="password" id="loginPassword" required>
                    <button class="btn btn-outline-secondary toggle-password" type="button">
                        <i class="bi bi-eye"></i>
                    </button>
                </div>
                <div class="invalid-feedback"></div>
            </div>
            <div class="d-grid mb-3">
                <button type="submit" class="btn btn-dark">
                    <span class="spinner-border spinner-border-sm" role="status" aria-hidden="true" style="display: none;"></span>
                    Log In
                </button>
            </div>
             <div class="d-flex justify-content-between align-items-center mb-3">
                <div class="form-check"><input class="form-check-input" type="checkbox" id="rememberMe"><label class="form-check-label" for="rememberMe">Remember me</label></div>
                <a href="#" class="text-decoration-none text-dark" id="forgotPasswordLink">Lost your password?</a>
            </div>
        </form>

        {{-- MODIFIED Forgot Password Form (Now Phone Based) --}}
        <form id="forgotPasswordForm" style="display: none;" novalidate>
            @csrf
            <p>Lost your password? Please enter your phone number. You will receive a verification code to create a new password.</p>
            <div class="mb-3">
                <label for="forgotPhone" class="form-label">Phone Number <span class="text-danger">*</span></label>
                 <div class="input-group">
                    <span class="input-group-text d-flex align-items-center gap-2">
                        <img src="https://flagcdn.com/w20/bd.png" width="20" alt="Bangladesh Flag">
                        +880
                    </span>
                    <input 
                        type="tel" 
                        class="form-control" 
                        id="forgotPhone" 
                        name="phone" 
                        required 
                        pattern="\d{10}"
                        maxlength="10" 
                        title="Please enter a 10-digit phone number (without the leading 0).">
                </div>
                <div id="forgotPhoneHelp" class="form-text text-danger">
                  Enter the 10 digits after +880 (e.g., 1712345678).
                </div>
                <div class="invalid-feedback">Please provide a valid 10-digit phone number.</div>
            </div>
             <div class="d-grid mb-3">
                <button type="submit" class="btn btn-dark">
                    <span class="spinner-border spinner-border-sm" role="status" aria-hidden="true" style="display: none;"></span>
                    Send OTP
                </button>
            </div>
             <a href="#" class="text-decoration-none text-dark" id="backToLoginLink">&larr; Back to Login</a>
        </form>

        {{-- Registration Form --}}
        <form id="registerForm" style="display: none;" novalidate>
             @csrf
            <div class="mb-3"><label for="registerName" class="form-label">Full Name <span class="text-danger">*</span></label><input type="text" class="form-control" id="registerName" name="name" required><div class="invalid-feedback"></div></div>
          
            <div class="mb-3"><label for="registerEmail" class="form-label">Email (Optional)</label><input type="email" class="form-control" id="registerEmail" name="email"><div class="invalid-feedback"></div></div>
            <div class="mb-3">
                <label for="registerPhone" class="form-label">Phone <span class="text-danger">*</span></label>
                <div class="input-group">
                    <span class="input-group-text d-flex align-items-center gap-2">
                        <img src="https://flagcdn.com/w20/bd.png" width="20" alt="Bangladesh Flag">
                        +880
                    </span>
                    <input 
                        type="tel" 
                        class="form-control" 
                        id="registerPhone" 
                        name="phone" 
                        required 
                        pattern="\d{10}"
                        maxlength="10" 
                        title="Please enter a 10-digit phone number (without the leading 0).">
                </div>
                <div id="phoneHelp" class="form-text text-danger">
                  Enter the 10 digits after +880 (e.g., 1712345678).
                </div>
                <div class="invalid-feedback">Please provide a valid 10-digit phone number.</div>
            </div>
            <div class="mb-3">
                <label for="registerPassword" class="form-label">Password <span class="text-danger">*</span></label>
                <div class="input-group">
                    <input type="password" class="form-control" autocomplete="new-password" 
       readonly 
       onfocus="this.removeAttribute('readonly');" id="registerPassword" name="password" required minlength="8">
                    <button class="btn btn-outline-secondary toggle-password" type="button"><i class="bi bi-eye"></i></button></div><div id="passwordHelp" class="form-text text-danger">Password must be at least 8 characters long.</div><div class="invalid-feedback"></div></div>
            <div class="mb-3">
                <label for="confirmPassword" class="form-label">Confirm Password <span class="text-danger">*</span></label>
                <div class="input-group">
                    <input type="password" class="form-control" autocomplete="new-password" 
       readonly 
       onfocus="this.removeAttribute('readonly');" id="confirmPassword" name="password_confirmation" required>
                    <button class="btn btn-outline-secondary toggle-password" type="button">
                        <i class="bi bi-eye"></i>
                    </button>
                </div>
                <div class="invalid-feedback"></div>
            </div>
           
            <div class="d-grid mb-3">
                <button type="submit" class="btn btn-dark">
                    <span class="spinner-border spinner-border-sm" role="status" aria-hidden="true" style="display: none;"></span>
                    Register
                </button>
            </div>
        </form>
        
        {{-- OTP Verification Form (Used for both Register and Reset) --}}
        <form id="otpForm" style="display: none;" novalidate>
            @csrf
            <p class="text-center">A 6-digit verification code has been sent to your phone. Please enter it below.</p>
            <div class="d-flex justify-content-center gap-2 mb-3" id="otp-inputs">
                <input type="text" class="form-control form-control-lg text-center otp-input" maxlength="1" required>
                <input type="text" class="form-control form-control-lg text-center otp-input" maxlength="1" required>
                <input type="text" class="form-control form-control-lg text-center otp-input" maxlength="1" required>
                <input type="text" class="form-control form-control-lg text-center otp-input" maxlength="1" required>
                <input type="text" class="form-control form-control-lg text-center otp-input" maxlength="1" required>
                <input type="text" class="form-control form-control-lg text-center otp-input" maxlength="1" required>
            </div>
             <div class="invalid-feedback d-block text-center mb-3"></div>
            <div class="d-grid mb-3">
                <button type="submit" class="btn btn-dark">
                    <span class="spinner-border spinner-border-sm" role="status" aria-hidden="true" style="display: none;"></span>
                    Verify OTP
                </button>
            </div>
            <div class="text-center">
                <p class="small">Didn't receive the code? <a href="#" id="resendOtpLink">Resend OTP</a></p>
                <span id="resend-loader" class="spinner-border spinner-border-sm" role="status" style="display: none;"></span>
            </div>
            <a href="#" class="text-decoration-none text-dark d-block text-center mt-3" id="backToLoginLinkOtp">&larr; Back to Login</a>
        </form>

        {{-- NEW Final Password Reset Form --}}
        <form id="resetPasswordFinalForm" style="display: none;" novalidate>
            @csrf
            <p>Please enter your new password.</p>
            <div class="mb-3">
                <label for="resetPasswordInput" class="form-label">New Password <span class="text-danger">*</span></label>
                <div class="input-group">
                    <input type="password" class="form-control" autocomplete="new-password" 
       readonly 
       onfocus="this.removeAttribute('readonly');" id="resetPasswordInput" name="password" required minlength="8">
                    <button class="btn btn-outline-secondary toggle-password" type="button"><i class="bi bi-eye"></i></button></div><div class="form-text text-danger">Password must be at least 8 characters long.</div><div class="invalid-feedback"></div></div>
            <div class="mb-3">
                <label for="resetConfirmPassword" class="form-label">Confirm New Password <span class="text-danger">*</span></label>
                <div class="input-group">
                    <input type="password" class="form-control" autocomplete="new-password" 
       readonly 
       onfocus="this.removeAttribute('readonly');" id="resetConfirmPassword" name="password_confirmation" required>
                    <button class="btn btn-outline-secondary toggle-password" type="button">
                        <i class="bi bi-eye"></i>
                    </button>
                </div>
                <div class="invalid-feedback"></div>
            </div>
           
            <div class="d-grid mb-3">
                <button type="submit" class="btn btn-dark">
                    <span class="spinner-border spinner-border-sm" role="status" aria-hidden="true" style="display: none;"></span>
                    Update Password
                </button>
            </div>
             <a href="#" class="text-decoration-none text-dark" id="backToLoginLinkReset">&larr; Back to Login</a>
        </form>


        <div id="authToggleSection" class="text-center">
            <i class="bi bi-person-circle fs-1 text-secondary"></i>
            <p class="mt-3" id="toggleText">No account yet?</p>
            <a href="#" class="btn btn-outline-dark rounded-pill px-4" id="toggleFormBtn">Create An Account</a>
        </div>
    </div>
</div>

<script>
// DYNAMIC AUTH SCRIPT
$(document).ready(function() {
    const offcanvasEl = document.getElementById('signInOffcanvas');
    const offcanvasTitle = $('#signInOffcanvasLabel');
    const loginForm = $('#loginForm');
    const registerForm = $('#registerForm');
    const otpForm = $('#otpForm');
    const forgotPasswordForm = $('#forgotPasswordForm');
    const resetPasswordFinalForm = $('#resetPasswordFinalForm'); // New Form
    const forgotPasswordLink = $('#forgotPasswordLink');
    const backToLoginLink = $('#backToLoginLink'); // On Forgot Form
    const backToLoginLinkOtp = $('#backToLoginLinkOtp'); // On OTP Form
    const backToLoginLinkReset = $('#backToLoginLinkReset'); // On Reset Form
    const toggleFormBtn = $('#toggleFormBtn');
    const toggleText = $('#toggleText');
    const authToggleSection = $('#authToggleSection');
    const authErrorDiv = $('#auth-error-message');

    // --- Helper Functions ---
    function clearErrors(form) {
        const scope = form ? form : $(document);
        scope.find('.form-control').removeClass('is-invalid is-valid'); // Clear validation
        scope.find('.invalid-feedback').text('');
        authErrorDiv.hide().text('');
    }

    function hideAllAuthForms() {
        loginForm.hide();
        registerForm.hide();
        forgotPasswordForm.hide();
        otpForm.hide();
        resetPasswordFinalForm.hide();
        authToggleSection.hide(); // Hide toggle by default
    }

    function showLoader(form) {
        form.find('button[type="submit"] .spinner-border').show();
        form.find('button[type="submit"]').prop('disabled', true);
    }

    function hideLoader(form) {
        form.find('button[type="submit"] .spinner-border').hide();
        form.find('button[type="submit"]').prop('disabled', false);
    }

    function displayErrors(errors, form) {
        clearErrors(form);
        $.each(errors, function(field, messages) {
            let fieldId = field;
            // Handle specific field name mismatches
            if (field === 'password_confirmation') {
                fieldId = 'confirmPassword'; // For register
                if (form.is('#resetPasswordFinalForm')) {
                     fieldId = 'resetConfirmPassword'; // For reset
                }
            }
             if (field === 'password') {
                 if (form.is('#resetPasswordFinalForm')) {
                     fieldId = 'resetPasswordInput';
                }
            }
            const input = form.find(`#${fieldId}, [name="${field}"]`).first();
            input.addClass('is-invalid');
            input.closest('.mb-3').find('.invalid-feedback').text(messages[0]);
        });
    }

    // --- Form Toggling Logic ---
    toggleFormBtn.on('click', function(e) {
        e.preventDefault();
        clearErrors(); // Clear all errors when toggling
        if (loginForm.is(':visible')) {
            // Show Register
            hideAllAuthForms();
            registerForm.show();
            authToggleSection.show();
            offcanvasTitle.text('Register');
            toggleText.text('Already have an account?');
            toggleFormBtn.text('Sign In');
        } else {
            // Show Login
            hideAllAuthForms();
            loginForm.show();
            authToggleSection.show();
            offcanvasTitle.text('Sign in');
            toggleText.text('No account yet?');
            toggleFormBtn.text('Create An Account');
        }
    });

    // --- Toggle to Forgot Password Form ---
    forgotPasswordLink.on('click', function(e) {
        e.preventDefault();
        clearErrors();
        hideAllAuthForms();
        forgotPasswordForm.show();
        offcanvasTitle.text('Reset Password');
    });

    // --- Toggle back to Login Form (from all back links) ---
    function goBackToLogin() {
        clearErrors();
        hideAllAuthForms();
        loginForm.show();
        authToggleSection.show();
        offcanvasTitle.text('Sign in');
    }
    backToLoginLink.on('click', function(e) { e.preventDefault(); goBackToLogin(); });
    backToLoginLinkOtp.on('click', function(e) { e.preventDefault(); goBackToLogin(); });
    backToLoginLinkReset.on('click', function(e) { e.preventDefault(); goBackToLogin(); });


    // --- Password Toggle (Global) ---
    // Unbind first to avoid multiple listeners if script is loaded multiple times
    $(document).off('click', '.toggle-password').on('click', '.toggle-password', function() {
        const input = $(this).closest('.input-group').find('input');
        const icon = $(this).find('i');
        if (input.attr('type') === 'password') {
            input.attr('type', 'text');
            icon.removeClass('bi-eye').addClass('bi-eye-slash');
        } else {
            input.attr('type', 'password');
            icon.removeClass('bi-eye-slash').addClass('bi-eye');
        }
    });

    // --- Login Form Submission ---
    loginForm.on('submit', function(e) {
        e.preventDefault();
        const currentForm = $(this);
        clearErrors(currentForm);
        showLoader(currentForm);
        
        $.ajax({
            url: '{{ route("customer.login") }}',
            method: 'POST',
            data: currentForm.serialize(),
            success: function(response) {
                if (response.success) {
                    window.location.href = response.redirect_url;
                }
            },
            error: function(xhr) {
                if (xhr.status === 422) {
                    displayErrors(xhr.responseJSON.errors, currentForm);
                } else {
                    authErrorDiv.text(xhr.responseJSON.message || 'An unexpected error occurred.').show();
                }
            },
            complete: function() {
                hideLoader(currentForm);
            }
        });
    });

    // --- Registration Form Submission ---
    registerForm.on('submit', function(e) {
        e.preventDefault();
        const currentForm = $(this);
        clearErrors(currentForm);
        showLoader(currentForm);
        
        const formData = new FormData(this);

        $.ajax({
            url: '{{ route("customer.register") }}',
            method: 'POST',
            data: formData,
            processData: false,
            contentType: false,
            success: function(response) {
                if (response.success) {
                    registerForm.hide();
                    otpForm.show();
                    otpForm.data('mode', 'register'); // Set mode for OTP form
                    authToggleSection.hide();
                    offcanvasTitle.text('Verify Your Account');
                }
            },
            error: function(xhr) {
                if (xhr.status === 422) {
                    displayErrors(xhr.responseJSON.errors, currentForm);
                } else {
                     authErrorDiv.text(xhr.responseJSON.message || 'An unexpected error occurred.').show();
                }
            },
            complete: function() {
                hideLoader(currentForm);
            }
        });
    });

     // --- MODIFIED Forgot Password Form Submission (Send OTP) ---
    forgotPasswordForm.on('submit', function(e) {
        e.preventDefault();
        const currentForm = $(this);
        clearErrors(currentForm);
        showLoader(currentForm);

        $.ajax({
            url: '{{ route("password.sendOtp") }}', // <-- New Route
            method: 'POST',
            data: currentForm.serialize(),
            success: function(response) {
                if(response.success){
                    forgotPasswordForm.hide();
                    otpForm.show();
                    otpForm.data('mode', 'reset'); // Set mode for OTP form
                    offcanvasTitle.text('Verify OTP');
                }
            },
            error: function(xhr) {
                if (xhr.status === 422) {
                    displayErrors(xhr.responseJSON.errors, currentForm);
                } else {
                    authErrorDiv.text(xhr.responseJSON.message || 'An unexpected error occurred.').show();
                }
            },
            complete: function() {
                hideLoader(currentForm);
            }
        });
    });

    // --- OTP Form Logic (NOW HANDLES BOTH MODES) ---
    const otpInputs = $('.otp-input');
    otpInputs.on('keyup', function(e) {
        if (e.key >= 0 && e.key <= 9) {
            $(this).next('.otp-input').focus();
        } else if (e.key === 'Backspace') {
            $(this).prev('.otp-input').focus();
        }
    });

    otpForm.on('submit', function(e) {
        e.preventDefault();
        const currentForm = $(this);
        const mode = currentForm.data('mode'); // 'register' or 'reset'
        
        clearErrors(currentForm);
        showLoader(currentForm);

        let otp = '';
        otpInputs.each(function() {
            otp += $(this).val();
        });

        let ajaxUrl;
        let ajaxData = {
            _token: '{{ csrf_token() }}',
            otp: otp
        };

        if (mode === 'register') {
            ajaxUrl = '{{ route("customer.verifyOtp") }}';
        } else if (mode === 'reset') {
            ajaxUrl = '{{ route("password.verifyOtp") }}'; // <-- New Route
        } else {
            authErrorDiv.text('An unknown error occurred. Please try again.').show();
            hideLoader(currentForm);
            return;
        }

        $.ajax({
            url: ajaxUrl,
            method: 'POST',
            data: ajaxData,
            success: function(response) {
                 if (response.success) {
                    if (mode === 'register') {
                        window.location.href = response.redirect_url;
                    } else if (mode === 'reset') {
                        otpForm.hide();
                        resetPasswordFinalForm.show();
                        offcanvasTitle.text('Set New Password');
                    }
                }
            },
            error: function(xhr) {
                 otpForm.find('.invalid-feedback').text(xhr.responseJSON.message || 'Verification failed.');
            },
            complete: function() {
                hideLoader(currentForm);
            }
        });
    });

    // --- NEW: Final Password Reset Form Submission ---
    resetPasswordFinalForm.on('submit', function(e) {
        e.preventDefault();
        const currentForm = $(this);
        clearErrors(currentForm);
        showLoader(currentForm);

        $.ajax({
            url: '{{ route("password.updateNew") }}', // <-- New Route
            method: 'POST',
            data: currentForm.serialize(),
            success: function(response) {
                if (response.success) {
                    // Show success message, then redirect
                     authErrorDiv.removeClass('alert-danger').addClass('alert-success').text('Password updated successfully! Redirecting...').show();
                     setTimeout(() => {
                         window.location.href = response.redirect_url;
                     }, 2000);
                }
            },
            error: function(xhr) {
                 if (xhr.status === 422) {
                    displayErrors(xhr.responseJSON.errors, currentForm);
                } else {
                    authErrorDiv.text(xhr.responseJSON.message || 'An unexpected error occurred.').show();
                }
            },
            complete: function() {
                hideLoader(currentForm);
            }
        });
    });


    // --- Resend OTP Logic (NOW HANDLES BOTH MODES) ---
    $('#resendOtpLink').on('click', function(e) {
        e.preventDefault();
        $('#resend-loader').show();
        $(this).hide();

        const mode = $('#otpForm').data('mode');
        let ajaxUrl;

        if (mode === 'register') {
            ajaxUrl = '{{ route("customer.resendOtp") }}';
        } else if (mode === 'reset') {
            ajaxUrl = '{{ route("password.resendOtp") }}'; // <-- New Route
        } else {
            Swal.fire({ icon: 'error', title: 'Error', text: 'Session expired. Please start over.' });
            $('#resend-loader').hide();
            $('#resendOtpLink').show();
            return;
        }

        $.ajax({
            url: ajaxUrl,
            method: 'POST',
            data: { _token: '{{ csrf_token() }}' },
            success: function(response) {
                Swal.fire({
                    toast: true,
                    position: 'top-end',
                    icon: 'success',
                    title: response.message,
                    showConfirmButton: false,
                    timer: 3000
                });
            },
            error: function(xhr) {
                Swal.fire({ icon: 'error', title: 'Error', text: xhr.responseJSON.message });
            },
            complete: function() {
                $('#resend-loader').hide();
                $('#resendOtpLink').show();
            }
        });
    });

    // --- Live Password Matching Logic (for Register Form) ---
    const registerPassword = $('#registerPassword');
    const confirmPassword = $('#confirmPassword');

    function validateRegisterPasswords() {
        const passVal = registerPassword.val();
        const confirmVal = confirmPassword.val();
        const confirmFeedback = confirmPassword.closest('.mb-3').find('.invalid-feedback');

        if (confirmVal.length === 0 && passVal.length === 0) {
            registerPassword.removeClass('is-valid is-invalid');
            confirmPassword.removeClass('is-valid is-invalid');
            confirmFeedback.text('');
            return;
        }

        if (passVal === confirmVal) {
            registerPassword.removeClass('is-invalid').addClass('is-valid');
            confirmPassword.removeClass('is-invalid').addClass('is-valid');
            confirmFeedback.text('');
        } else {
            registerPassword.removeClass('is-valid').addClass('is-invalid');
            confirmPassword.removeClass('is-valid').addClass('is-invalid');
            confirmFeedback.text('Passwords do not match.');
        }
    }
    registerPassword.on('keyup', validateRegisterPasswords);
    confirmPassword.on('keyup', validateRegisterPasswords);
    
    // --- NEW: Live Password Matching Logic (for Reset Form) ---
    const resetPasswordInput = $('#resetPasswordInput');
    const resetConfirmPassword = $('#resetConfirmPassword');

    function validateResetPasswords() {
        const passVal = resetPasswordInput.val();
        const confirmVal = resetConfirmPassword.val();
        const confirmFeedback = resetConfirmPassword.closest('.mb-3').find('.invalid-feedback');

         if (confirmVal.length === 0 && passVal.length === 0) {
            resetPasswordInput.removeClass('is-valid is-invalid');
            resetConfirmPassword.removeClass('is-valid is-invalid');
            confirmFeedback.text('');
            return;
        }

        if (passVal === confirmVal) {
            resetPasswordInput.removeClass('is-invalid').addClass('is-valid');
            resetConfirmPassword.removeClass('is-invalid').addClass('is-valid');
            confirmFeedback.text('');
        } else {
            resetPasswordInput.removeClass('is-valid').addClass('is-invalid');
            resetConfirmPassword.removeClass('is-valid').addClass('is-invalid');
            confirmFeedback.text('Passwords do not match.');
        }
    }
    resetPasswordInput.on('keyup', validateResetPasswords);
    resetConfirmPassword.on('keyup', validateResetPasswords);

    
    // --- Phone Number Input Formatting (for Register and Forgot) ---
    function formatPhoneNumber() {
        let value = $(this).val();
        value = value.replace(/\D/g, '');
        if (value.startsWith('0')) {
            value = value.substring(1);
        }
        if (value.length > 10) {
            value = value.slice(0, 10);
        }
        $(this).val(value);
    }
    $('#registerPhone').on('input', formatPhoneNumber);
    $('#forgotPhone').on('input', formatPhoneNumber); // Added for new form
});
</script>