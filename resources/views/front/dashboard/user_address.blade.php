@extends('front.master.master')
@section('title', 'Manage Addresses')

@section('body')
{{-- Custom CSS for the custom dropdowns and loader --}}
<style>
    .custom-select-wrapper { position: relative; width: 100%; }
    .custom-select { display: flex; justify-content: space-between; align-items: center; padding: 0.5rem 0.75rem; border: 1px solid #ced4da; border-radius: 0.375rem; cursor: pointer; background-color: #fff; height: calc(1.5em + 1rem + 2px); }
    .custom-select.is-invalid { border-color: #dc3545; }
    .custom-select-options { display: none; position: absolute; top: 100%; left: 0; right: 0; background-color: #fff; border: 1px solid #ced4da; border-radius: 0.375rem; z-index: 1060; max-height: 200px; overflow-y: auto; margin-top: 4px; }
    .custom-select-options.show { display: block; }
    .custom-select-search { width: 100%; padding: 0.5rem 0.75rem; border: none; border-bottom: 1px solid #eee; outline: none; }
    .custom-select-options .options-list { max-height: 150px; overflow-y: auto; }
    .custom-select-options .option { padding: 0.5rem 0.75rem; cursor: pointer; }
    .custom-select-options .option:hover { background-color: #f8f9fa; }
    .custom-select-placeholder { color: #6c757d; }
    
    /* Loader styles */
    #loader-overlay {
        position: fixed;
        top: 0;
        left: 0;
        width: 100%;
        height: 100%;
        background-color: rgba(255, 255, 255, 0.7);
        z-index: 1099; /* Higher than modal z-index */
        display: none; /* Initially hidden */
        justify-content: center;
        align-items: center;
    }
</style>

<main>
    <section class="section">
        <div class="container py-4">
            <div class="spotlight_user_profile_container">
                <div class="spotlight_user_profile_breadcrumb">
                    <a href="{{ route('home.index') }}" class="text-decoration-none">Home</a> > <a href="{{ route('dashboard.user') }}" class="text-decoration-none">Account</a> > Manage Address
                </div>
                <div class="row">
                    <!-- Left Sidebar -->
                    <div class="col-lg-3 col-md-4 mb-4">
                        @include('front.include.dashboardSidebar')
                    </div>

                    <!-- Main Content Area -->
                    <div class="col-lg-9 col-md-8">
                        <div class="spotlight_user_profile_main-content">
                            <div class="spotlight_user_profile_main-header"><h4>Manage Address</h4></div>
                            <div class="d-flex justify-content-end mb-3">
                                <button class="btn btn-primary" data-bs-toggle="modal" data-bs-target="#addAddressModal"><i class="bi bi-plus-lg me-2"></i> Add New Address</button>
                            </div>
                            <div id="address-list-container">
                                @forelse($user->addresses as $address)
                                    @include('front.dashboard.partials._address_card', ['address' => $address, 'user' => $user])
                                @empty
                                    <div class="alert alert-info text-center" id="no-address-alert">You have not saved any addresses yet.</div>
                                @endforelse
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </section>
</main>

<!-- Loader Overlay -->
<div id="loader-overlay">
    <div class="spinner-border text-primary" style="width: 3rem; height: 3rem;" role="status">
        <span class="visually-hidden">Loading...</span>
    </div>
</div>


<!-- Add Address Modal -->
<div class="modal fade" id="addAddressModal" tabindex="-1" aria-labelledby="addAddressModalLabel" aria-hidden="true">
    <div class="modal-dialog modal-dialog-centered">
        <div class="modal-content">
            <div class="modal-header"><h5 class="modal-title" id="addAddressModalLabel">Add New Address</h5><button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button></div>
            <div class="modal-body">
                <form id="add-address-form" novalidate>
                    @csrf
                    <div class="mb-3">
                        <label class="form-label">District *</label>
                        <div class="custom-select-wrapper">
                            <div class="custom-select" data-target="add-district"><span class="custom-select-placeholder">Select a district...</span><i class="bi bi-chevron-down"></i></div>
                            <div class="custom-select-options"><input type="text" class="custom-select-search" placeholder="Search districts..."><div class="options-list"></div></div>
                        </div>
                        <input type="hidden" name="district" id="add-district" required><div class="invalid-feedback"></div>
                    </div>
                    <div class="mb-3">
                        <label class="form-label">Upazila/Thana *</label>
                        <div class="custom-select-wrapper">
                            <div class="custom-select" data-target="add-upazila"><span class="custom-select-placeholder">Select a district first...</span><i class="bi bi-chevron-down"></i></div>
                             <div class="custom-select-options"><input type="text" class="custom-select-search" placeholder="Search upazilas..."><div class="options-list"></div></div>
                        </div>
                        <input type="hidden" name="upazila" id="add-upazila" required><div class="invalid-feedback"></div>
                    </div>
                    <div class="mb-3"><label for="add-address" class="form-label">Address (House/Road/Area) *</label><textarea class="form-control" id="add-address" name="address" required></textarea><div class="invalid-feedback"></div></div>
                    <div class="mb-3">
                        <label class="form-label">Address Type *</label>
                        <div>
                            <input type="radio" class="btn-check" name="address_type" id="add-Home" value="Home" autocomplete="off" checked><label class="btn btn-outline-secondary me-2" for="add-Home"><i class="bi bi-house-door-fill me-1"></i> Home</label>
                            <input type="radio" class="btn-check" name="address_type" id="add-Office" value="Office" autocomplete="off"><label class="btn btn-outline-secondary me-2" for="add-Office"><i class="bi bi-building-fill me-1"></i> Office</label>
                            <input type="radio" class="btn-check" name="address_type" id="add-Others" value="Others" autocomplete="off"><label class="btn btn-outline-secondary" for="add-Others"><i class="bi bi-geo-alt-fill me-1"></i> Others</label>
                        </div>
                    </div>
                    <div class="form-check form-switch mb-3"><input class="form-check-input" type="checkbox" id="add-is_default" name="is_default" value="1"><label class="form-check-label" for="add-is_default">Make this my default address</label></div>
                    <button type="submit" class="btn btn-success w-100">Save Address</button>
                </form>
            </div>
        </div>
    </div>
</div>

<!-- Edit Address Modal -->
<div class="modal fade" id="editAddressModal" tabindex="-1" aria-labelledby="editAddressModalLabel" aria-hidden="true">
    <div class="modal-dialog modal-dialog-centered">
        <div class="modal-content">
            <div class="modal-header"><h5 class="modal-title" id="editAddressModalLabel">Edit Address</h5><button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button></div>
            <div class="modal-body">
                <form id="edit-address-form" novalidate>
                    @csrf
                    <input type="hidden" name="address_id" id="edit-address_id">
                    <div class="mb-3">
                        <label class="form-label">District *</label>
                        <div class="custom-select-wrapper">
                            <div class="custom-select" data-target="edit-district"><span class="custom-select-placeholder">Select a district...</span><i class="bi bi-chevron-down"></i></div>
                            <div class="custom-select-options"><input type="text" class="custom-select-search" placeholder="Search districts..."><div class="options-list"></div></div>
                        </div>
                        <input type="hidden" name="district" id="edit-district" required><div class="invalid-feedback"></div>
                    </div>
                    <div class="mb-3">
                        <label class="form-label">Upazila/Thana *</label>
                        <div class="custom-select-wrapper">
                            <div class="custom-select" data-target="edit-upazila"><span class="custom-select-placeholder">Select a district first...</span><i class="bi bi-chevron-down"></i></div>
                             <div class="custom-select-options"><input type="text" class="custom-select-search" placeholder="Search upazilas..."><div class="options-list"></div></div>
                        </div>
                        <input type="hidden" name="upazila" id="edit-upazila" required><div class="invalid-feedback"></div>
                    </div>
                    <div class="mb-3"><label for="edit-address" class="form-label">Address (House/Road/Area) *</label><textarea class="form-control" id="edit-address" name="address" required></textarea><div class="invalid-feedback"></div></div>
                    <div class="mb-3">
                        <label class="form-label">Address Type *</label>
                        <div>
                            <input type="radio" class="btn-check" name="address_type" id="edit-Home" value="Home" autocomplete="off"><label class="btn btn-outline-secondary me-2" for="edit-Home"><i class="bi bi-house-door-fill me-1"></i> Home</label>
                            <input type="radio" class="btn-check" name="address_type" id="edit-Office" value="Office" autocomplete="off"><label class="btn btn-outline-secondary me-2" for="edit-Office"><i class="bi bi-building-fill me-1"></i> Office</label>
                          <input type="radio" class="btn-check" name="address_type" id="edit-Others" value="Others" autocomplete="off"><label class="btn btn-outline-secondary" for="edit-Others"><i class="bi bi-geo-alt-fill me-1"></i> Others</label>
                        </div>
                    </div>
                    <div class="form-check form-switch mb-3"><input class="form-check-input" type="checkbox" id="edit-is_default" name="is_default" value="1"><label class="form-check-label" for="edit-is_default">Make this my default address</label></div>
                    <button type="submit" class="btn btn-success w-100">Save Changes</button>
                </form>
            </div>
        </div>
    </div>
</div>
@endsection

@section('script')
<script>
$(document).ready(function() {
    // --- SETUP ---
    const addAddressModal = new bootstrap.Modal(document.getElementById('addAddressModal'));
    const editAddressModal = new bootstrap.Modal(document.getElementById('editAddressModal'));
    const addAddressForm = $('#add-address-form');
    const editAddressForm = $('#edit-address-form');
    let districtsLoaded = false;
    let districtsCache = [];

    // --- LOADER FUNCTIONS ---
    function showLoader() {
        $('#loader-overlay').css('display', 'flex');
    }
    function hideLoader() {
        $('#loader-overlay').hide();
    }

    // --- GENERIC HELPER FUNCTIONS ---
    function initializeCustomSelect(wrapper) {
        const selectTrigger = wrapper.find('.custom-select');
        const optionsContainer = wrapper.find('.custom-select-options');
        const searchInput = wrapper.find('.custom-select-search');
        const optionsList = wrapper.find('.options-list');
        const hiddenInput = $(`#${selectTrigger.data('target')}`);
        const placeholder = selectTrigger.find('.custom-select-placeholder');

        selectTrigger.on('click', function() {
            $('.custom-select-options').not(optionsContainer).removeClass('show');
            optionsContainer.toggleClass('show');
            if (optionsContainer.hasClass('show')) {
                searchInput.focus();
            }
        });

        searchInput.on('keyup', function() {
            const filter = $(this).val().toUpperCase();
            optionsList.find('.option').each(function() {
                const txtValue = $(this).text();
                $(this).css('display', txtValue.toUpperCase().indexOf(filter) > -1 ? '' : 'none');
            });
        });

        optionsList.on('click', '.option', function() {
            const value = $(this).data('value');
            placeholder.text(value).removeClass('custom-select-placeholder');
            hiddenInput.val(value).trigger('change');
            optionsContainer.removeClass('show');
        });
    }
    
    $('.custom-select-wrapper').each(function() {
        initializeCustomSelect($(this));
    });

    $(document).on('click', function(e) {
        if (!$(e.target).closest('.custom-select-wrapper').length) {
            $('.custom-select-options').removeClass('show');
        }
    });

    function loadDistricts(targetWrapper, callback) {
        if (districtsLoaded) {
            populateDistrictOptions(targetWrapper, districtsCache);
            if (callback) callback();
            return;
        }
        const optionsList = targetWrapper.find('.options-list');
        optionsList.html('<div class="p-3 text-center"><span class="spinner-border spinner-border-sm"></span></div>');
        
        $.ajax({
            url: '{{ route("locations.districts") }}',
            method: 'GET',
            success: function(data) {
                districtsCache = data;
                districtsLoaded = true;
                populateDistrictOptions(targetWrapper, districtsCache);
                if (callback) callback();
            }
        });
    }

    function populateDistrictOptions(targetWrapper, districts) {
        const optionsList = targetWrapper.find('.options-list');
        optionsList.empty();
        districts.forEach(district => {
            optionsList.append(`<div class="option" data-value="${district}">${district}</div>`);
        });
    }

    function loadUpazilas(district, targetWrapper, upazilaToSelect = null) {
        const upazilaOptionsList = targetWrapper.find('.options-list');
        const upazilaPlaceholder = targetWrapper.find('.custom-select-placeholder');
        const upazilaHiddenInput = $(`#${targetWrapper.find('.custom-select').data('target')}`);

        upazilaOptionsList.html('<div class="p-3 text-center"><span class="spinner-border spinner-border-sm"></span></div>');
        upazilaPlaceholder.text('Loading...').addClass('custom-select-placeholder');
        upazilaHiddenInput.val('');

        if (!district) {
            upazilaPlaceholder.text('Select a district first...');
            upazilaOptionsList.empty();
            return;
        }

        $.ajax({
            url: `{{ route('locations.upazilas') }}?district=${encodeURIComponent(district)}`,
            method: 'GET',
            success: function(data) {
                upazilaOptionsList.empty();
                data.forEach(upazila => {
                    upazilaOptionsList.append(`<div class="option" data-value="${upazila}">${upazila}</div>`);
                });
                upazilaPlaceholder.text('Select an upazila...');

                if (upazilaToSelect) {
                    upazilaHiddenInput.val(upazilaToSelect);
                    upazilaPlaceholder.text(upazilaToSelect).removeClass('custom-select-placeholder');
                }
            }
        });
    }

    // --- EVENT HANDLERS ---
    $('#addAddressModal').on('shown.bs.modal', function() {
        addAddressForm[0].reset();
        const districtWrapper = $('.custom-select[data-target="add-district"]').closest('.custom-select-wrapper');
        loadDistricts(districtWrapper);
        $('.custom-select[data-target="add-district"] .custom-select-placeholder').text('Select a district...').addClass('custom-select-placeholder');
        $('.custom-select[data-target="add-upazila"] .custom-select-placeholder').text('Select a district first...').addClass('custom-select-placeholder');
        $('.custom-select[data-target="add-upazila"]').closest('.custom-select-wrapper').find('.options-list').empty();
    });

    $('input#add-district').on('change', function() {
        const upazilaWrapper = $('.custom-select[data-target="add-upazila"]').closest('.custom-select-wrapper');
        loadUpazilas($(this).val(), upazilaWrapper);
    });

    addAddressForm.on('submit', function(e) {
        e.preventDefault();
        showLoader();
        $.ajax({
            url: '{{ route("dashboard.address.store") }}',
            method: 'POST',
            data: $(this).serialize(),
            success: function(response) {
                if(response.success){
                    addAddressModal.hide();
                    Swal.fire({ icon: 'success', title: 'Success!', text: response.message, showConfirmButton: false, timer: 1500 });
                    $('#no-address-alert').hide();
                    $('#address-list-container').append(response.newAddressHtml);
                }
            },
            error: function(xhr) {
                 Swal.fire({ icon: 'error', title: 'Error!', text: 'An unexpected error occurred.' });
            },
            complete: function() {
                hideLoader();
            }
        });
    });

    $('#address-list-container').on('click', '.edit-address-btn', function() {
        const addressData = $(this).data('address');
        editAddressForm[0].reset();
        
        $('#edit-address_id').val(addressData.id);
        $(`input[name="address_type"][value="${addressData.address_type}"]`).prop('checked', true);
        $('#edit-is_default').prop('checked', addressData.is_default);

        const addressParts = addressData.address.split(', ').map(part => part.trim());
        const district = addressParts.length > 2 ? addressParts[addressParts.length - 1] : '';
        const upazila = addressParts.length > 1 ? addressParts[addressParts.length - 2] : '';
        const streetAddress = addressParts.slice(0, addressParts.length - 2).join(', ');
        $('#edit-address').val(streetAddress || addressParts[0] || '');
        
        const districtWrapper = $('.custom-select[data-target="edit-district"]').closest('.custom-select-wrapper');
        const upazilaWrapper = $('.custom-select[data-target="edit-upazila"]').closest('.custom-select-wrapper');
        
        loadDistricts(districtWrapper, function() {
            if (district) {
                $('#edit-district').val(district);
                districtWrapper.find('.custom-select-placeholder').text(district).removeClass('custom-select-placeholder');
                loadUpazilas(district, upazilaWrapper, upazila);
            }
        });

        editAddressModal.show();
    });

    $('input#edit-district').on('change', function() {
        const upazilaWrapper = $('.custom-select[data-target="edit-upazila"]').closest('.custom-select-wrapper');
        loadUpazilas($(this).val(), upazilaWrapper);
    });

    editAddressForm.on('submit', function(e) {
        e.preventDefault();
        showLoader();
        $.ajax({
            url: '{{ route("dashboard.address.update") }}',
            method: 'POST',
            data: $(this).serialize(),
            success: function(response) {
                if(response.success){
                    editAddressModal.hide();
                    Swal.fire({ icon: 'success', title: 'Success!', text: response.message, showConfirmButton: false, timer: 1500 });
                    $('#address-card-' + response.addressId).replaceWith(response.updatedAddressHtml);
                }
            },
            error: function(xhr) {
                 Swal.fire({ icon: 'error', title: 'Error!', text: 'An unexpected error occurred.' });
            },
            complete: function() {
                hideLoader();
            }
        });
    });

    $('#address-list-container').on('click', '.delete-address-btn', function() {
        const addressId = $(this).data('id');
        Swal.fire({
            title: 'Are you sure?',
            text: "You won't be able to revert this!",
            icon: 'warning',
            showCancelButton: true,
            confirmButtonColor: '#d33',
            cancelButtonColor: '#3085d6',
            confirmButtonText: 'Yes, delete it!'
        }).then((result) => {
            if (result.isConfirmed) {
                showLoader();
                $.ajax({
                    url: '{{ route("dashboard.address.delete") }}',
                    method: 'POST',
                    data: { _token: '{{ csrf_token() }}', address_id: addressId },
                    success: function(response) {
                        $('#address-card-' + addressId).fadeOut(300, function() { $(this).remove(); });
                        Swal.fire({ toast: true, position: 'top-end', icon: 'success', title: response.message, showConfirmButton: false, timer: 2000 });
                    },
                    error: function() { 
                        Swal.fire({ icon: 'error', title: 'Error!', text: 'Could not delete the address.' });
                    },
                    complete: function() {
                        hideLoader();
                    }
                });
            }
        });
    });

    $('#address-list-container').on('click', '.set-default-btn', function() {
        const addressId = $(this).data('id');
        showLoader();
         $.ajax({
            url: '{{ route("dashboard.address.setDefault") }}',
            method: 'POST',
            data: { _token: '{{ csrf_token() }}', address_id: addressId },
            success: function(response) {
                Swal.fire({ toast: true, position: 'top-end', icon: 'success', title: response.message, showConfirmButton: false, timer: 1500 });
                $('#address-list-container').html(response.allAddressesHtml);
            },
            error: function() { 
                Swal.fire({ icon: 'error', title: 'Error!', text: 'Could not set default address.' });
            },
            complete: function() {
                hideLoader();
            }
        });
    });
});
</script>
@endsection

