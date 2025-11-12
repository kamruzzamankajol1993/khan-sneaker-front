@extends('front.master.master')
@section('title', 'Product Reviews')

@section('css')
<style>
    /* Star rating styles */
    .star-rating .bi-star,
    .star-rating .bi-star-fill {
        color: #ffc107; /* Yellow color for stars */
        cursor: pointer;
    }
    .star-rating .bi-star {
        color: #e4e5e9; /* Grey for unselected stars */
    }

    /* Image preview styles */
    .image-preview-container {
        display: flex;
        flex-wrap: wrap; /* Allow previews to wrap to the next line */
        gap: 10px;
        margin-top: 10px;
    }
    .image-preview-item {
        position: relative;
        width: 80px; /* Fixed width for preview */
        height: 80px; /* Fixed height for preview */
        border: 1px solid #ddd;
        border-radius: 5px;
        overflow: hidden; /* Hide overflow for images */
    }
    .image-preview-item img {
        width: 100%;
        height: 100%;
        object-fit: cover; /* Cover the area without distortion */
    }
    .remove-image-btn {
        position: absolute;
        top: -5px;
        right: -5px;
        background: rgba(220, 53, 69, 0.9); /* Red with some transparency */
        color: white;
        border: none;
        border-radius: 50%;
        width: 20px;
        height: 20px;
        display: flex;
        align-items: center;
        justify-content: center;
        font-size: 12px;
        line-height: 1; /* Adjust line height for better centering */
        cursor: pointer;
        padding: 0; /* Remove default padding */
        z-index: 10; /* Ensure button is above image */
    }
</style>
@endsection

@section('body')
<main>
    <section class="section">
        <div class="container">
            <div class="spotlight_user_profile_container">
                <div class="spotlight_user_profile_breadcrumb">
                    <a href="{{ route('home.index') }}">Home</a> > <a href="{{ route('dashboard.user') }}">Account</a> > Product Reviews
                </div>
                <div class="row">
                    <div class="col-lg-3 col-md-4 mb-4">
                        @include('front.include.dashboardSidebar')
                    </div>
                    <div class="col-lg-9 col-md-8">
                        <div class="spotlight_user_profile_main-content">
                            <div class="spotlight_user_profile_main-header">
                                <h4>Products to Review</h4>
                            </div>
                            
                            @forelse ($productsToReview as $product)
                                <div class="card mb-3">
                                    <div class="card-body d-flex justify-content-between align-items-center">
                                        <div class="d-flex align-items-center">
                                            @php
                                                // Assuming product->main_image is an array and we want the first one
                                                $image = is_array($product->main_image) && count($product->main_image) > 0 ? $product->main_image[0] : null;
                                            @endphp
                                            <img src="{{ $image ? $front_ins_url .'public/uploads/'.$image : 'https://placehold.co/80x80' }}" alt="{{ $product->name }}" class="me-3 rounded" style="width: 80px; height: 80px; object-fit: cover;">
                                            <div>
                                                <h6 class="mb-0">{{ $product->name }}</h6>
                                                <small class="text-muted">{{ $product->category->name ?? 'N/A' }}</small>
                                            </div>
                                        </div>
                                        <button class="btn btn-dark write-review-btn" 
                                                data-product-id="{{ $product->id }}"
                                                data-product-name="{{ $product->name }}"
                                                data-product-image="{{ $image ? asset('public/uploads/'.$image) : 'https://placehold.co/80x80' }}">
                                            Write a Review
                                        </button>
                                    </div>
                                </div>
                            @empty
                                <div class="alert alert-info text-center">You have no purchased items to review at the moment.</div>
                            @endforelse

                            <div class="mt-4">
                                {{ $productsToReview->links() }}
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </section>
</main>

<div class="modal fade" id="reviewModal" tabindex="-1" aria-labelledby="reviewModalLabel" aria-hidden="true">
    <div class="modal-dialog modal-dialog-centered">
        <div class="modal-content">
            <div class="modal-header">
                <h5 class="modal-title" id="reviewModalLabel">Write a review for</h5>
                <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
            </div>
            <div class="modal-body">
                <form id="review-form" enctype="multipart/form-data">
                    @csrf
                    <input type="hidden" name="product_id" id="review_product_id">
                    <div class="d-flex align-items-center mb-3">
                        <img id="review-product-image" src="" alt="" class="me-3 rounded" style="width: 60px;">
                        <h6 id="review-product-name" class="mb-0"></h6>
                    </div>
                    <div class="mb-3">
                        <label class="form-label">Your Rating <span class="text-danger">*</span></label>
                        <div class="star-rating fs-4" id="star-rating-input">
                            <i class="bi bi-star" data-value="1"></i>
                            <i class="bi bi-star" data-value="2"></i>
                            <i class="bi bi-star" data-value="3"></i>
                            <i class="bi bi-star" data-value="4"></i>
                            <i class="bi bi-star" data-value="5"></i>
                        </div>
                        <input type="hidden" name="rating" id="rating-value" required>
                    </div>
                    <div class="mb-3">
                        <label for="description" class="form-label">Your Review</label>
                        <textarea name="description" id="description" class="form-control" rows="4" placeholder="Share your experience..."></textarea>
                    </div>
                    <div class="mb-3">
                        <label for="images" class="form-label">Add Photos (optional, max 2MB each)</label>
                        {{-- IMPORTANT: Added 'multiple' attribute here --}}
                        <input type="file" name="images[]" id="images" class="form-control" multiple accept="image/jpeg,image/png,image/gif">
                        <div class="image-preview-container" id="image-previews"></div>
                    </div>
                    <button type="submit" class="btn btn-dark w-100">Submit Review</button>
                </form>
            </div>
        </div>
    </div>
</div>
@endsection

@section('script')
<script>
$(document).ready(function() {
    const reviewModal = new bootstrap.Modal(document.getElementById('reviewModal'));
    let selectedRating = 0;
    let reviewFiles = []; // This array will hold the actual File objects

    // Open and populate the review modal
    $('.write-review-btn').on('click', function() {
        const productId = $(this).data('productId');
        const productName = $(this).data('productName');
        const productImage = $(this).data('productImage');

        $('#review_product_id').val(productId);
        $('#review-product-name').text(productName);
        $('#review-product-image').attr('src', productImage);

        // Reset form fields and state
        $('#review-form')[0].reset();
        $('#star-rating-input i').removeClass('bi-star-fill').addClass('bi-star');
        selectedRating = 0;
        $('#rating-value').val(''); // Clear hidden rating input
        reviewFiles = []; // Clear stored files
        $('#image-previews').html(''); // Clear image previews

        reviewModal.show();
    });

    // Star rating logic
    $('#star-rating-input i').on('mouseenter', function() {
        const rating = $(this).data('value');
        $('#star-rating-input i').each(function() {
            $(this).toggleClass('bi-star-fill', $(this).data('value') <= rating);
            $(this).toggleClass('bi-star', $(this).data('value') > rating);
        });
    }).on('mouseleave', function() {
        $('#star-rating-input i').each(function() {
            $(this).toggleClass('bi-star-fill', $(this).data('value') <= selectedRating);
            $(this).toggleClass('bi-star', $(this).data('value') > selectedRating);
        });
    }).on('click', function() {
        selectedRating = $(this).data('value');
        $('#rating-value').val(selectedRating);
        // Ensure stars remain filled after click
        $('#star-rating-input i').each(function() {
            $(this).toggleClass('bi-star-fill', $(this).data('value') <= selectedRating);
            $(this).toggleClass('bi-star', $(this).data('value') > selectedRating);
        });
    });

    // Multiple image preview logic
    $('#images').on('change', function(event) {
        // Add new files to the existing array
        reviewFiles.push(...Array.from(event.target.files));
        renderImagePreviews();
        // Clear the input's value to allow selecting the same file again if needed
        $(this).val(''); 
    });
    
    function renderImagePreviews() {
        const container = $('#image-previews').html(''); // Clear existing previews
        reviewFiles.forEach((file, index) => {
            const reader = new FileReader();
            reader.onload = function(e) {
                const previewHtml = `
                    <div class="image-preview-item">
                        <img src="${e.target.result}" alt="Preview">
                        <button type="button" class="remove-image-btn" data-index="${index}">&times;</button>
                    </div>`;
                container.append(previewHtml);
            };
            reader.readAsDataURL(file);
        });
    }

    // Handle removing an image from previews
    $(document).on('click', '.remove-image-btn', function() {
        const indexToRemove = $(this).data('index');
        reviewFiles.splice(indexToRemove, 1); // Remove file from array
        renderImagePreviews(); // Re-render previews
    });

    // Handle review form submission
    $('#review-form').on('submit', function(e) {
        e.preventDefault();
        
        if (selectedRating === 0) {
            Swal.fire('Incomplete', 'Please select a star rating.', 'warning');
            return;
        }

        const formData = new FormData();
        formData.append('_token', '{{ csrf_token() }}');
        formData.append('product_id', $('#review_product_id').val());
        formData.append('rating', $('#rating-value').val());
        formData.append('description', $('#description').val());

        // Append all selected files
        reviewFiles.forEach((file, index) => {
            formData.append(`images[${index}]`, file);
        });

        const button = $(this).find('button[type="submit"]');
        button.prop('disabled', true).html('<span class="spinner-border spinner-border-sm"></span> Submitting...');

        $.ajax({
            url: '{{ route("reviews.store") }}',
            method: 'POST',
            data: formData,
            processData: false, // Important for FormData
            contentType: false, // Important for FormData
            success: function(response) {
                if(response.success) {
                    reviewModal.hide();
                    Swal.fire({ 
                        icon: 'success', 
                        title: 'Success!', 
                        text: response.message, 
                        showConfirmButton: false, 
                        timer: 2000,
                        timerProgressBar: true
                    });
                    setTimeout(() => location.reload(), 2000); // Reload to update product list
                }
            },
            error: function(xhr) {
                Swal.fire({ icon: 'error', title: 'Oops...', text: xhr.responseJSON.message || 'An error occurred.' });
            },
            complete: function() {
                button.prop('disabled', false).text('Submit Review');
            }
        });
    });
});
</script>
@endsection
