@extends('front.master.master')

@section('title', 'Reset Your Password')

@section('body')
<main>
    <section class="section">
        <div class="container py-5">
            <div class="row justify-content-center">
                <div class="col-md-6">
                    <div class="card shadow-sm">
                        <div class="card-body p-4">
                            <h3 class="card-title text-center mb-4">Set a New Password</h3>

                            <div id="reset-error-message" class="alert alert-danger" style="display: none;"></div>
                            
                            <form id="passwordResetForm" novalidate>
                                @csrf
                                <input type="hidden" name="token" value="{{ $token }}">
                                <input type="hidden" name="email" value="{{ $email }}">

                                <div class="mb-3">
                                    <label for="password" class="form-label">New Password *</label>
                                    <input type="password" class="form-control" name="password" id="password" required>
                                    <div class="invalid-feedback"></div>
                                </div>
                                <div class="mb-3">
                                    <label for="password_confirmation" class="form-label">Confirm New Password *</label>
                                    <input type="password" class="form-control" name="password_confirmation" id="password_confirmation" required>
                                    <div class="invalid-feedback"></div>
                                </div>
                                <div class="d-grid">
                                    <button type="submit" class="btn btn-dark">
                                        <span class="spinner-border spinner-border-sm" role="status" aria-hidden="true" style="display: none;"></span>
                                        Reset Password
                                    </button>
                                </div>
                            </form>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </section>
</main>
@endsection

@section('script')
<script>
$(document).ready(function() {
    const form = $('#passwordResetForm');
    const errorDiv = $('#reset-error-message');

    function clearErrors() {
        $('.form-control').removeClass('is-invalid');
        $('.invalid-feedback').text('');
        errorDiv.hide().text('');
    }

    function showLoader() {
        form.find('button[type="submit"] .spinner-border').show();
        form.find('button[type="submit"]').prop('disabled', true);
    }

    function hideLoader() {
        form.find('button[type="submit"] .spinner-border').hide();
        form.find('button[type="submit"]').prop('disabled', false);
    }
    
    function displayErrors(errors) {
        clearErrors();
        $.each(errors, function(field, messages) {
            const input = $(`[name="${field}"]`);
            input.addClass('is-invalid');
            input.closest('.mb-3').find('.invalid-feedback').text(messages[0]);
        });
    }

    form.on('submit', function(e) {
        e.preventDefault();
        clearErrors();
        showLoader();

        $.ajax({
            url: '{{ route("password.update") }}',
            method: 'POST',
            data: $(this).serialize(),
            success: function(response) {
                if (response.success) {
                    Swal.fire({
                        icon: 'success',
                        title: 'Success!',
                        text: 'Your password has been reset successfully. You will be redirected to your dashboard.',
                        timer: 3000,
                        timerProgressBar: true,
                        willClose: () => {
                             window.location.href = response.redirect_url;
                        }
                    });
                }
            },
            error: function(xhr) {
                 if (xhr.status === 422) {
                    displayErrors(xhr.responseJSON.errors);
                } else {
                    errorDiv.text(xhr.responseJSON.message || 'An unexpected error occurred.').show();
                }
            },
            complete: function() {
                hideLoader();
            }
        });
    });
});
</script>
@endsection
