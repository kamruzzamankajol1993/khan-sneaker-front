@extends('front.master.master')

@section('title', 'My Dashboard')

@section('css')
<style>
    .spotlight_user_profile_profile-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 2rem; /* Adds some space below the header */
}
/* Target the h4 title within the header */
.spotlight_user_profile_profile-header h4 {
    margin: 0; /* Removes default heading margin for better alignment */
    flex-shrink: 0; /* Prevents the title from shrinking */
}

/* Target the update button specifically within the header */
.spotlight_user_profile_profile-header .spotlight_user_profile_update-btn {
    width: auto;      /* Let the button's width be determined by its content */
    flex-grow: 0;     /* IMPORTANT: Stops the button from stretching to fill empty space */
    padding: 8px 25px;/* Adjust padding to make the button smaller. (Top/Bottom Left/Right) */
}
.spotlight_user_profile_form-group {
    margin-bottom: 1.5rem; /* Adjust this value for more or less space */
}
</style>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/flatpickr/dist/flatpickr.min.css">
@endsection

@section('body')
<main>
            <section class="section">
                <div class="container">
                    <div class="spotlight_user_profile_container">
                        <div class="spotlight_user_profile_breadcrumb">
                            Home > Account
                        </div>

                        <div class="row">
                            <!-- Left Sidebar -->
                            <div class="col-lg-3 col-md-4 mb-4">
                                @include('front.include.dashboardSidebar')
                            </div>

                            <!-- Main Content Area -->
                            <div class="col-lg-9 col-md-8">
                                <div class="spotlight_user_profile_main-content">
                                    <div class="spotlight_user_profile_profile-header">
    <h4>View Profile</h4>
    <button class="btn spotlight_user_profile_update-btn" id="update-profile-info-btn">Update Profile</button>
</div>

                                    <div class="spotlight_user_profile_profile-picture-section">
                                      <div class="spotlight_user_profile_profile-picture" id="main-profile-picture" @if(Auth::user()->image) style="background: transparent;" @endif>
                                    @if(Auth::user()->image)
                                        <img src="{{ asset('public/' . Auth::user()->image) }}" style="height: 70px;" alt="Profile Picture">
                                    @else
                                        <i class="bi bi-person-fill"></i>
                                    @endif
                                    <div class="spotlight_user_profile_camera-icon" id="change-picture-btn" style="cursor: pointer;">
                                        <i class="bi bi-camera-fill"></i>
                                    </div>
                                </div>
                                    </div>
{{-- Hidden file input for image upload --}}
                            <input type="file" id="profile-image-input" name="profile_image" style="display: none;" accept="image/*">
                                         <div class="row">
                                <div class="col-md-12">
                                    <div class="spotlight_user_profile_form-group">
                                        <label for="fullName" class="spotlight_user_profile_form-label">Full Name *</label>
                                        <input type="text" id="fullName" class="form-control" value="{{ $user->name }}">
                                    </div>
                                </div>
                            </div>

                            <div class="row">
                                <div class="col-md-6">
                                    <div class="spotlight_user_profile_form-group">
                                        <label for="gender" class="spotlight_user_profile_form-label">Gender</label>
                                        <select id="gender" class="form-select">
                                            <option value="">Select Gender</option>
                                            <option value="Male" {{ optional(Auth::user())->gender == 'Male' ? 'selected' : '' }}>Male</option>
                                            <option value="Female" {{ optional(Auth::user())->gender == 'Female' ? 'selected' : '' }}>Female</option>
                                            <option value="Other" {{ optional(Auth::user())->gender == 'Other' ? 'selected' : '' }}>Other</option>
                                        </select>
                                    </div>
                                </div>
                                <div class="col-md-6">
                                    <div class="spotlight_user_profile_form-group">
                                        <label for="dob" class="spotlight_user_profile_form-label">Date of Birth</label>
                                        <input type="text" id="dob" class="form-control" placeholder="YYYY-MM-DD" value="{{ optional(Auth::user())->dob }}">
                                    </div>
                                </div>
                            </div>

                            <div class="row">
                                <div class="col-md-6">
                                    <div class="spotlight_user_profile_form-group">
                                        <label for="email" class="spotlight_user_profile_form-label">Email Address</label>
                                        <div class="input-group">
                                            <input type="email" id="email" class="form-control" value="{{ Auth::user()->email }}">
                                            @if(Auth::user()->email_verified_at)
                                                <span class="input-group-text" title="Verified"><i class="bi bi-check-circle-fill text-success"></i></span>
                                            @endif
                                        </div>
                                    </div>
                                </div>
                                <div class="col-md-6">
                                    <div class="spotlight_user_profile_form-group">
                                        <label for="mobile" class="spotlight_user_profile_form-label">Mobile No</label>
                                        <div class="input-group">
                                            <input type="tel" id="mobile" class="form-control" value="{{ Auth::user()->phone }}">
                                            @if(Auth::user()->email_verified_at)
                                                 <span class="input-group-text" title="Verified"><i class="bi bi-check-circle-fill text-success"></i></span>

                                                 @else
                                        <button class="btn btn-outline-secondary spotlight_user_profile_update-btn"  style="background-color: #e9ecef; color: #333; border-color: #ddd;" id="update-mobile-btn" data-field="email">Verify</button>

                                            @endif
                                            
                                        </div>
                                    </div>
                                </div>
                            </div>

                            <div class="row">
                                <div class="col-md-12">
                                    <div class="spotlight_user_profile_form-group">
                                        <label for="secondary_phone" class="spotlight_user_profile_form-label">Secondary Mobile No</label>
                                        <input type="tel" id="secondary_phone" class="form-control" value="{{ optional(Auth::user())->secondary_phone }}">
                                    </div>
                                </div>
                            </div>

                            </div>

                            {{-- <div class="row mt-4">
                                <div class="col-12">
                                    <button class="btn spotlight_user_profile_update-btn" id="update-profile-info-btn">Update Profile</button>
                                </div>
                            </div> --}}
                        </div>
                    </div>
                </div>
            </section>
        </main>

        <!-- OTP Verification Modal -->
<div class="modal fade" id="otpVerificationModal" tabindex="-1" aria-labelledby="otpVerificationModalLabel" aria-hidden="true">
    <div class="modal-dialog modal-dialog-centered">
        <div class="modal-content">
            <div class="modal-header">
                <h5 class="modal-title" id="otpVerificationModalLabel">Verify Your Update</h5>
                <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
            </div>
            <div class="modal-body">
                <p class="text-center">A 6-digit code has been sent. Please enter it below.</p>
                <form id="otp-verify-form">
                    <div class="d-flex justify-content-center gap-2 mb-3">
                        <input type="text" class="form-control form-control-lg text-center otp-input" maxlength="1" required>
                        <input type="text" class="form-control form-control-lg text-center otp-input" maxlength="1" required>
                        <input type="text" class="form-control form-control-lg text-center otp-input" maxlength="1" required>
                        <input type="text" class="form-control form-control-lg text-center otp-input" maxlength="1" required>
                        <input type="text" class="form-control form-control-lg text-center otp-input" maxlength="1" required>
                        <input type="text" class="form-control form-control-lg text-center otp-input" maxlength="1" required>
                    </div>
                    <div id="otp-error" class="invalid-feedback d-block text-center mb-3"></div>
                    <button type="submit" class="btn btn-dark w-100">Verify & Update</button>
                </form>
            </div>
        </div>
    </div>
</div>
@endsection

@section('script')
<script src="https://cdn.jsdelivr.net/npm/flatpickr"></script>
<script>
$(document).ready(function() {

    flatpickr("#dob", {
        dateFormat: "d-m-Y",
        altInput: true,
        altFormat: "F j, Y",
        maxDate: "today"
    });

    // --- PROFILE PICTURE UPLOAD LOGIC ---
    
    // 1. Trigger hidden file input when camera icon is clicked
    $('#change-picture-btn').on('click', function() {
        $('#profile-image-input').click();
    });

    // 2. Handle the file selection and upload via AJAX
    $('#profile-image-input').on('change', function() {
        const file = this.files[0];
        if (file) {
            const formData = new FormData();
            formData.append('profile_image', file);
            formData.append('_token', '{{ csrf_token() }}');

            $.ajax({
                url: '{{ route("dashboard.picture.update") }}',
                method: 'POST',
                data: formData,
                processData: false, // Important for file uploads
                contentType: false, // Important for file uploads
               success: function(response) {
    if (response.success) {
        // Create the new image HTML
        const newImageHtml = `<img src="${response.image_url}" style="height: 70px;" alt="User Avatar">`;
        
        // Update the main profile picture
        const mainProfileContainer = $('#main-profile-picture');
        mainProfileContainer.find('img, i').first().remove(); 
        mainProfileContainer.prepend(newImageHtml.replace('User Avatar', 'Profile Picture'));
        
        // **Remove the gray background**
        mainProfileContainer.css('background', 'transparent');

        // Update the sidebar profile picture
        const sidebarProfileContainer = $('#sidebar-avatar-container'); // Assuming this is the correct ID
        sidebarProfileContainer.html(newImageHtml.replace('User Avatar', 'Sidebar Avatar'));

        // **Also remove the gray background from the sidebar version**
        sidebarProfileContainer.css('background', 'transparent');

        Swal.fire({
            // toast: true,
            // position: 'top-end',
            icon: 'success',
            title: response.message,
            showConfirmButton: false,
            timer: 3000
        });
    }
},
                error: function(xhr) {
                    const errorMessage = xhr.responseJSON ? xhr.responseJSON.message : 'An unknown error occurred.';
                    Swal.fire({
                        icon: 'error',
                        title: 'Upload Failed',
                        text: errorMessage
                    });
                }
            });
        }
    });

    // --- PROFILE INFO & OTP VERIFICATION LOGIC ---
    const otpModal = new bootstrap.Modal(document.getElementById('otpVerificationModal'));

    // 1. Handle simple profile info update (Name, Gender, DOB)
    $('#update-profile-info-btn').on('click', function(e) {
        e.preventDefault();

        // --- START: NEW VALIDATION LOGIC ---
        const currentEmail = $('#email').val().trim();
        const originalEmail = '{{ Auth::user()->email }}';
        const currentPhone = $('#mobile').val().trim();
        const originalPhone = '{{ Auth::user()->phone }}';

        if (currentEmail !== originalEmail) {
            Swal.fire({
                icon: 'warning',
                title: 'Verification Required',
                text: 'To change your email, please use the "Verify" button next to the email field to change email.'
            });
            return; // Stop the function here
        }

        if (currentPhone !== originalPhone) {
            Swal.fire({
                icon: 'warning',
                title: 'Verification Required',
                text: 'To change your mobile number, please use the "Update" button next to the mobile field to start the verification process.'
            });
            return; // Stop the function here
        }
        // --- END: NEW VALIDATION LOGIC ---

        const button = $(this);
        button.prop('disabled', true).text('Updating...');

        $.ajax({
            url: '{{ route("dashboard.profile.info.update") }}',
            method: 'POST',
            data: {
                _token: '{{ csrf_token() }}',
                name: $('#fullName').val(),
                gender: $('#gender').val(),
                dob: $('#dob').val(),
                                secondary_phone: $('#secondary_phone').val(),
            },
            success: function(response) {
                if(response.success){
                    $('.spotlight_user_profile_user-name').text(response.newName);
                    Swal.fire({  icon: 'success', title: response.message, showConfirmButton: false, timer: 3000 });
                }
            },
            error: function(xhr) {
                Swal.fire({ icon: 'error', title: 'Error', text: xhr.responseJSON.message });
            },
            complete: function() {
                button.prop('disabled', false).text('Update Profile');
            }
        });
    });

    // 2. Handle click on "Update" for Email or Phone
    $('#update-email-btn, #update-mobile-btn').on('click', function() {
        const field = $(this).data('field');
        const value = $(`#${field}`).val().trim();
        const originalEmail = '{{ Auth::user()->email }}';
        const originalPhone = '{{ Auth::user()->phone }}';
        
        if ((field === 'email' && value === originalEmail) || (field === 'phone' && value === originalPhone)) {
            Swal.fire({ icon: 'info', title: 'No Changes', text: `Your ${field} is already set to this value.`});
            return;
        }

        Swal.fire({
            title: `Update ${field}?`,
            text: `An OTP will be sent to ${value} for verification.`,
            icon: 'info',
            showCancelButton: true,
            confirmButtonText: 'Send OTP',
        }).then((result) => {
            if (result.isConfirmed) {
                sendOtpRequest(field, value);
            }
        });
    });
    
    // 3. AJAX function to request the OTP
    function sendOtpRequest(field, value) {
        $.ajax({
            url: '{{ route("dashboard.send.otp") }}',
            method: 'POST',
            data: { _token: '{{ csrf_token() }}', field: field, value: value },
            success: function(response) {
                if(response.success){
                    Swal.fire({ toast: true, position: 'top-end', icon: 'success', title: response.message, showConfirmButton: false, timer: 4000 });
                    otpModal.show();
                }
            },
            error: function(xhr) {
                Swal.fire({ icon: 'error', title: 'Error', text: xhr.responseJSON.message });
            }
        });
    }

    // 4. Handle OTP form submission
    $('#otp-verify-form').on('submit', function(e) {
        e.preventDefault();
        let otp = '';
        $('#otpVerificationModal .otp-input').each(function() { otp += $(this).val(); });
        
        $('#otp-error').text('');

        $.ajax({
            url: '{{ route("dashboard.verify.update") }}',
            method: 'POST',
            data: { _token: '{{ csrf_token() }}', otp: otp },
            success: function(response) {
                if(response.success){
                    otpModal.hide();
                    Swal.fire({ icon: 'success', title: 'Success!', text: response.message, showConfirmButton: false, timer: 2000 });
                    setTimeout(() => location.reload(), 2000); 
                }
            },
            error: function(xhr) {
                $('#otp-error').text(xhr.responseJSON.message);
            }
        });
    });
    
    // Auto-focus logic for OTP inputs
    $('.otp-input').on('keyup', function(e) {
        if (e.key >= 0 && e.key <= 9 && $(this).val() != '') {
            $(this).next('.otp-input').focus();
        } else if (e.key === 'Backspace') {
            $(this).prev('.otp-input').focus();
        }
    });
});
</script>
@endsection
