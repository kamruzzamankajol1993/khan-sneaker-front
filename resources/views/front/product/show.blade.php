@extends('front.master.master')

@section('title')
{{ $product->name }}
@endsection
@section('css')
<style>
   
#realImageModal .modal-body,
#mainImageModal .modal-body {
    padding: 0.5rem; /* Add some padding around the slider */
}

.real-image-slider .slick-slide img {
    width: 100%;
    max-height: 75vh; /* Ensure image is not taller than the screen */
    object-fit: contain; /* Show the full image without cropping */
    margin: auto;
}

/* Slick slider arrow customization for the modal */
.real-image-slider .slick-prev,
.real-image-slider .slick-next {
    /* MODIFIED: Increased z-index to appear above the modal content */
    z-index: 1060; 
    width: 40px;
    height: 40px;
}
.real-image-slider .slick-prev { left: 25px; }
.real-image-slider .slick-next { right: 25px; }

.real-image-slider .slick-prev:before,
.real-image-slider .slick-next:before {
    font-size: 30px;
    opacity: .75;
    color: #333; /* Make sure your slick.css or slick-theme.css is loaded for the arrow font */
}
    #customer-reviews-section {
    position: relative;
    background-size: cover;
    background-position: center;
    background-attachment: fixed; /* Optional: Creates a cool parallax scrolling effect */
    z-index: 1;
}

#customer-reviews-section::before {
    content: '';
    position: absolute;
    top: 0;
    left: 0;
    right: 0;
    bottom: 0;
    background-color: rgba(255, 255, 255, 0.92); /* White overlay with 92% opacity */
    z-index: -1; /* Places the overlay behind the content */
}
    /* Style for color swatches */
    .color-option {
        width: 35px;
        height: 35px;
        border-radius: 50%;
        cursor: pointer;
        border: 2px solid #ddd;
        transition: transform 0.2s, border-color 0.2s;
        display: inline-block;
    }
    .color-option.active {
        border-color: #000;
        transform: scale(1.15);
        box-shadow: 0 0 8px rgba(0,0,0,0.3);
    }
    /* Style for size buttons */
    .size-option.active {
        background-color: #212529 !important;
        color: #fff !important;
        border-color: #212529 !important;
    }
    .size-option:disabled {
        cursor: not-allowed;
        opacity: 0.5;
        text-decoration: line-through;
    }
     .star-rating .bi-star-fill { color: #ffc107; }
    .review-images-container img { width: 70px; height: 70px; object-fit: cover; border-radius: 5px; cursor: pointer; }

    /* NEW: Add cursor pointer to main slider images */
    #main-product-slider .slick-slide img {
        cursor: pointer;
    }
</style>
@endsection
@section('body')
<main>
        <section class="section">
            <div class="container">
                <div class="product-container container my-5 p-4 bg-white rounded-4 shadow">

                    <div class="d-flex align-items-center text-muted small mb-4">
                         <a href="{{ url('/') }}" class="text-muted text-decoration-none">Home</a>
                    @if($product->category)
                        <span class="mx-2">/</span>
                        <a href="{{ route('category.show', $product->category->slug) }}" class="text-muted text-decoration-none">{{ $product->category->name }}</a>
                    @endif
                    @if($product->subcategory)
                        <span class="mx-2">/</span>
                        <a href="{{ route('subcategory.show', $product->subcategory->slug) }}" class="text-muted text-decoration-none">{{ $product->subcategory->name }}</a>
                    @endif
                    <span class="mx-2">/</span>
                    <span class="fw-semibold text-dark">{{ $product->name }}</span>
                    </div>

                    <div class="row g-4">
                        <div class="col-12 col-lg-6"> <div class="d-flex">
        <div class="d-flex flex-column align-items-center">
            <div id="thumbnail-nav-slider" class="w-100" style="max-width: 100px;">
                @php
                    $initialThumbnails = $product->thumbnail_image ?? [];
                    $firstVariant = $product->variants->first();
                    if ($firstVariant && is_array($firstVariant->variant_image)) {
                        $initialThumbnails = array_merge($initialThumbnails, $firstVariant->variant_image);
                    }
                    $imageCount = count($initialThumbnails);
                    if ($imageCount > 0 && $imageCount < 4) {
                        $needed = 4 - $imageCount;
                        for ($i = 0; $i < $needed; $i++) {
                            $initialThumbnails[] = $initialThumbnails[$i % $imageCount];
                        }
                    }
                @endphp
                @forelse ($initialThumbnails as $thumb)
                    <div><img src="{{ $front_ins_url . 'public/uploads/' . $thumb }}" alt="Thumbnail Image" class="img-fluid rounded-3 thumbnail-image"></div>
                @empty
                    <div><img src="https://placehold.co/100x100/F5F5F5/4B5563?text=No+Image" alt="No Thumbnail" class="img-fluid rounded-3"></div>
                @endforelse
            </div>
            <div class="custom-arrows d-flex justify-content-start align-items-center w-100 mt-2">
                <button class="prev-arrow"><i class="bi bi-chevron-up"></i></button>
                <button class="next-arrow"><i class="bi bi-chevron-down"></i></button>
            </div>
        </div>

        <div id="main-product-slider" class="flex-grow-1 rounded-3 overflow-hidden ms-4">
            @php
                $initialMainImages = $product->main_image ?? [];
                if ($firstVariant && is_array($firstVariant->main_image)) {
                    $initialMainImages = array_merge($initialMainImages, $firstVariant->main_image);
                }
                $imageCount = count($initialMainImages);
                if ($imageCount > 0 && $imageCount < 4) {
                    $needed = 4 - $imageCount;
                    for ($i = 0; $i < $needed; $i++) {
                        $initialMainImages[] = $initialMainImages[$i % $imageCount];
                    }
                }
            @endphp
            @forelse ($initialMainImages as $image)
                <div><img src="{{ $front_ins_url . 'public/uploads/' . $image }}" alt="{{ $product->name }}" class="img-fluid rounded-3"></div>
            @empty
                <div><img src="https://placehold.co/1000x1000/F5F5F5/4B5563?text=No+Image" alt="No Product Image" class="img-fluid rounded-3"></div>
            @endforelse
        </div>
    </div>
    <div class="d-flex align-items-center justify-content-center mt-3  p-3 rounded-3" data-product-id="{{ $product->id }}">
    <i class="bi bi-eye text-muted me-2"></i>
         <span id="watching-count">{{ $product->view_count }} </span> <span style="padding-left: 5px;">People watching this product now!</span>
    </div>
</div>

                        <div class="col-12 col-lg-6 d-flex flex-column p-4 spotlight_product_details">
                            <div class="d-flex flex-wrap align-items-center justify-content-between mb-2">
    <h1 class="h3 fw-semibold text-dark mb-0">{{ $product->name }}</h1>

    {{-- Show this button ONLY if real_image exist --}}
    @if(isset($product->real_image) && is_array($product->real_image) && count($product->real_image) > 0)
        <button class="btn btn-sm btn-outline-dark fw-semibold" data-bs-toggle="modal" data-bs-target="#realImageModal">
            <i class="bi bi-camera me-1"></i>
            Real Image
        </button>
    @endif
</div>
                            <p class="h6 text-muted mb-4">SKU: <span id="product-sku">{{ $product->product_code }}</span></p>
                            <div class="d-flex align-items-baseline mb-4">
                                @if($product->discount_price)
                                <span class="h3 fw-bold text-dark" id="product-price">৳ {{ number_format($product->discount_price, 2) }}</span>
                                <span class="h6 text-muted text-decoration-line-through ms-2" id="product-base-price">৳ {{ number_format($product->base_price, 2) }}</span>
                                @php
                                    $discountPercentage = round((($product->base_price - $product->discount_price) / $product->base_price) * 100);
                                @endphp
                                <span class="ms-4 badge bg-danger fw-bold">-{{ $discountPercentage }}% OFF</span>
                            @else
                                <span class="h3 fw-bold text-dark" id="product-price">৳ {{ number_format($product->base_price, 2) }}</span>
                                <span class="h6 text-muted text-decoration-line-through ms-2" id="product-base-price" style="display: none;"></span>
                            @endif
                            </div>

                            @if($product->variants->isNotEmpty() && $product->variants->first()->color)
                        <div class="mb-4">
                            <h2 class="h5 fw-semibold mb-2">Color: <span id="selected-color-name">{{ $product->variants->first()->color->name }}</span></h2>
                            <div class="d-flex gap-2">
                                @foreach($product->variants as $variant)
                                    <div class="color-option {{ $loop->first ? 'active' : '' }}"
                                         style="background-color: {{ $variant->color->code }};"
                                         data-variant-id="{{ $variant->id }}"
                                         data-variant-sku="{{ $variant->variant_sku }}"
                                         data-color-name="{{ $variant->color->name }}"
                                         data-additional-price="{{ $variant->additional_price }}"
                                         data-sizes="{{ json_encode($variant->detailed_sizes) }}"
                                         data-main-images="{{ json_encode(array_merge($product->main_image ?? [], $variant->main_image ?? [])) }}"
                                         data-thumb-images="{{ json_encode(array_merge($product->thumbnail_image ?? [], $variant->variant_image ?? [])) }}">
                                    </div>
                                @endforeach
                            </div>
                        </div>
                        @endif

                            <div class="mb-4">
                            <p class="mb-2">Size: <span id="selected-size-name" class="fw-semibold text-dark">Select a size</span></p>
                            <div id="size-options-container" class="d-flex gap-2">
                                {{-- Size buttons will be dynamically inserted here by JavaScript --}}
                            </div>
                        </div>
                         @if($product->assignChart && $product->assignChart->entries->isNotEmpty())
                        <div class="mb-4">
                            <h2 class="h5 fw-semibold mb-2">Size Chart:</h2>
                            <table class="table table-bordered table-sm text-center">
                                <thead>
                                    <tr class="bg-light">
                                        @foreach($product->assignChart->entries->first()->toArray() as $key => $value)
                                            @if(!in_array($key, ['id', 'assign_chart_id', 'created_at', 'updated_at']))
                                                <th class="p-2 text-uppercase">{{ str_replace('_', ' ', $key) }}</th>
                                            @endif
                                        @endforeach
                                    </tr>
                                </thead>
                                <tbody>
                                    @foreach($product->assignChart->entries as $entry)
                                    <tr>
                                        @foreach($entry->toArray() as $key => $value)
                                            @if(!in_array($key, ['id', 'assign_chart_id', 'created_at', 'updated_at']))
                                                <td class="p-2">{{ $value }}"</td>
                                            @endif
                                        @endforeach
                                    </tr>
                                    @endforeach
                                </tbody>
                            </table>
                        </div>
                        @endif

                            <div class="d-flex flex-column flex-sm-row align-items-center gap-4 mb-4">
                            <div class="d-flex align-items-center border rounded-3 overflow-hidden">
                                <button class="btn btn-light rounded-0" id="quantity-minus">-</button>
                                <span class="px-3" id="quantity-value">1</span>
                                <button class="btn btn-light rounded-0" id="quantity-plus">+</button>
                            </div>
                            <button class="btn btn-dark fw-semibold rounded-3 flex-grow-1 add-to-cart-button" id="add-to-cart">Add To Cart</button>
                            <button class="btn btn-secondary fw-semibold rounded-3 flex-grow-1 buy-button" id="buy-now">Buy Now</button>
                        </div>

                            <div class="d-flex flex-column flex-sm-row align-items-center justify-content-between mt-4">
                                <div class="d-flex align-items-center gap-2 mb-4 mb-sm-0">
    <a href="#" id="add-to-compare" class="btn btn-sm btn-outline-secondary d-flex align-items-center">
        <i class="bi bi-plus-circle me-2"></i>
        <span>Add to compare</span>
    </a>
    <a href="#" id="add-to-wishlist" class="btn btn-sm btn-outline-secondary d-flex align-items-center">
        <i class="bi bi-heart me-2"></i>
        <span>Add to wishlist</span>
    </a>
</div>
                                 @php
                                    $shareUrl = urlencode(url()->current());
                                    $shareTitle = urlencode($product->name);
                                    $facebookShareUrl = "https://www.facebook.com/sharer/sharer.php?u=" . $shareUrl;
                                    $twitterShareUrl = "https://twitter.com/intent/tweet?url=" . $shareUrl . "&text=" . $shareTitle;
                                    $linkedinShareUrl = "https://www.linkedin.com/sharing/share-offsite/?url=" . $shareUrl;
                                    $whatsappShareUrl = "https://api.whatsapp.com/send?text=" . $shareTitle . "%20" . $shareUrl;
                                @endphp
                                <div class="d-flex align-items-center text-secondary">
                                    <span>Share:</span>
                                    <a href="{{ $facebookShareUrl }}" target="_blank" class="ms-2 text-decoration-none text-secondary" title="Share on Facebook"><i class="bi bi-facebook fs-5"></i></a>
                                    <a href="{{ $twitterShareUrl }}" target="_blank" class="ms-2 text-decoration-none text-secondary" title="Share on X"><i class="bi bi-twitter-x fs-5"></i></a>
                                    <a href="{{ $linkedinShareUrl }}" target="_blank" class="ms-2 text-decoration-none text-secondary" title="Share on LinkedIn"><i class="bi bi-linkedin fs-5"></i></a>
                                    <a href="{{ $whatsappShareUrl }}" target="_blank" class="ms-2 text-decoration-none text-secondary" title="Share on WhatsApp"><i class="bi bi-whatsapp fs-5"></i></a>
                                </div>
                            </div>

                            <div class="mt-4 pt-4 border-top">
                                {{-- <div class="d-flex align-items-center bg-light p-3 rounded-3 mb-3">
                                    <i class="bi bi-eye text-muted me-2"></i>
                                    <span class="small text-muted">18 People watching this product now!</span>
                                </div> --}}

                                <div class="bg-white border p-3 rounded-3 mb-3">

                                    @foreach($areaWisePrice as $area)
                                    <div class="d-flex justify-content-between align-items-center mb-2">
                                        <div class="d-flex align-items-center">
                                            <i class="bi bi-truck me-2"></i>
                                            <span class="small">{{ $area->label }}</span>
                                        </div>
                                        <div class="d-flex align-items-center small text-muted">
                                            <span>{{$area->days}} Days</span>
                                            <span class="fw-semibold text-dark ms-3">{{$area->area}} BDT {{$area->price}}</span>
                                        </div>
                                    </div>
                                    @endforeach

                                </div>

                                <div>
                                    <h3 class="small fw-semibold mb-2">Payment Methods:</h3>
                                    <div class="d-flex align-items-center gap-2">
                                        <img src="https://placehold.co/40x20/F5F5F5/4B5563?text=Bank" alt="Bank"
                                            class="img-fluid" style="height: 20px;">
                                        <img src="https://placehold.co/40x20/F5F5F5/4B5563?text=Bikash" alt="Bikash"
                                            class="img-fluid" style="height: 20px;">
                                        <img src="https://placehold.co/40x20/F5F5F5/4B5563?text=Visa" alt="Visa"
                                            class="img-fluid" style="height: 20px;">
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </section>
        @php
    // Get the first main image for the background, with a fallback.
    $reviewBgImage = (is_array($product->main_image) && count($product->main_image) > 0)
                   ? $front_ins_url . 'public/uploads/' . $product->main_image[0]
                   : ''; 
@endphp
        <section class="section" id="customer-reviews-section" style="background-image: url('{{ $reviewBgImage }}');">
        <div class="container">
            <h2 class="h5 fw-semibold mb-3">Description</h2>
            <div class="bg-white p-4 rounded-3 border">
               {!! $product->description !!}
            </div>

            <h2 class="h5 fw-semibold mt-5 mb-3">Customer Reviews</h2>
            <div class="row g-4">
                <div class="col-12 col-lg-5 p-4 rounded-3 border bg-white">
                    @if($product->reviews_count > 0)
                    <div class="text-center mb-4">
                        <div class="star-rating fs-3 mb-2">
                            @for ($i = 1; $i <= 5; $i++)
                                <i class="bi {{ $i <= round($product->average_rating) ? 'bi-star-fill' : 'bi-star' }}"></i>
                            @endfor
                        </div>
                        <p class="text-muted">{{ $product->reviews_count }} {{ Str::plural('review', $product->reviews_count) }}</p>
                        <p class="mt-4 small fw-semibold">Overall Rating: {{ $product->average_rating }}/5.0</p>
                    </div>
                    @php
                        // Calculate rating percentages
                        $ratingCounts = $product->reviews->groupBy('rating')->map->count();
                        $ratingPercentages = [];
                        for ($i = 5; $i >= 1; $i--) {
                            $count = $ratingCounts->get($i, 0);
                            $percentage = ($product->reviews_count > 0) ? ($count / $product->reviews_count) * 100 : 0;
                            $ratingPercentages[$i] = ['count' => $count, 'percentage' => $percentage];
                        }
                    @endphp
                    <div class="space-y-2">
                        @foreach($ratingPercentages as $star => $data)
                        <div class="d-flex align-items-center">
                            <span class="small">{{ $star }} Star</span>
                            <div class="review-bar-container mx-2">
                                <div class="review-bar-fill" style="width: {{ $data['percentage'] }}%;"></div>
                            </div>
                            <span class="small text-muted">{{ $data['count'] }}</span>
                        </div>
                        @endforeach
                    </div>
                   @else
<div class="text-center py-4">
    {{-- This section now shows 5 empty stars for products with no reviews --}}
    <div class="star-rating fs-3 mb-2">
        @for ($i = 1; $i <= 5; $i++)
            <i class="bi bi-star text-muted"></i>
        @endfor
    </div>
    <p class="text-muted mb-1">This product has no reviews yet.</p>
    <p class="small">Be the first to review!</p>
</div>
@endif
                </div>

                <div class="col-12 col-lg-7">
                    @forelse($product->reviews as $review)
                    <div class="bg-white p-3 rounded-3 border mb-3">
                        <div class="d-flex align-items-start">
                            <img src="{{ optional($review->user)->image ? asset('public/'.optional($review->user)->image) : 'https://placehold.co/50x50' }}" alt="{{ optional($review->user)->name }}" class="rounded-circle" style="width: 50px; height: 50px;">
                            <div class="ms-3">
                                <h6 class="mb-0">{{ optional($review->user)->name ?? 'Anonymous' }}</h6>
                                <div class="star-rating text-muted small">
                                    @for ($i = 1; $i <= 5; $i++)
                                        <i class="bi {{ $i <= $review->rating ? 'bi-star-fill' : 'bi-star' }}"></i>
                                    @endfor
                                    <span class="ms-2">{{ \Carbon\Carbon::parse($review->created_at)->diffForHumans() }}</span>
                                </div>
                            </div>
                        </div>
                        <p class="mt-3 mb-2">{{ $review->description }}</p>
                        @if($review->images->isNotEmpty())
                        <div class="review-images-container">
                            @foreach($review->images as $image)
                                <img src="{{ asset('public/'.$image->image_path) }}" alt="Review image">
                            @endforeach
                        </div>
                        @endif
                    </div>
                    @empty
                    <div class="bg-white p-4 rounded-3 border d-flex align-items-center justify-content-center h-100">
                        <p class="text-muted">There are no reviews to display.</p>
                    </div>
                    @endforelse
                </div>
            </div>
        </div>
    </section>
    </main>

    <div class="modal fade" id="mainImageModal" tabindex="-1" aria-labelledby="mainImageModalLabel" aria-hidden="true">
        <div class="modal-dialog modal-dialog-centered modal-xl">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title" id="mainImageModalLabel">{{ $product->name }}</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                </div>
                <div class="modal-body">
                    <div id="main-image-modal-slider" class="real-image-slider">
                        @php
                            // Re-using the same logic from the main slider for initial load
                            $initialMainImages = $product->main_image ?? [];
                            $firstVariant = $product->variants->first();
                            if ($firstVariant && is_array($firstVariant->main_image)) {
                                $initialMainImages = array_merge($initialMainImages, $firstVariant->main_image);
                            }
                            $imageCount = count($initialMainImages);
                            if ($imageCount > 0 && $imageCount < 4) {
                                $needed = 4 - $imageCount;
                                for ($i = 0; $i < $needed; $i++) {
                                    $initialMainImages[] = $initialMainImages[$i % $imageCount];
                                }
                            }
                        @endphp
                        @forelse ($initialMainImages as $image)
                            <div>
                                <img src="{{ $front_ins_url . 'public/uploads/' . $image }}" alt="{{ $product->name }}">
                            </div>
                        @empty
                            <div>
                                <img src="https://placehold.co/1000x1000/F5F5F5/4B5563?text=No+Image" alt="No Product Image">
                            </div>
                        @endforelse
                    </div>
                </div>
            </div>
        </div>
    </div>

    {{-- Real Image Viewer Modal --}}
@if(isset($product->real_image) && is_array($product->real_image) && count($product->real_image) > 0)
<div class="modal fade" id="realImageModal" tabindex="-1" aria-labelledby="realImageModalLabel" aria-hidden="true">
    <div class="modal-dialog modal-dialog-centered modal-xl">
        <div class="modal-content">
            <div class="modal-header">
                <h5 class="modal-title" id="realImageModalLabel">{{ $product->name }} - Real Images</h5>
                <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
            </div>
            <div class="modal-body">
                <div id="real-image-slider" class="real-image-slider">
                    @foreach($product->real_image as $image)
                        <div>
                            <img src="{{ $front_ins_url . 'public/uploads/' . $image }}" alt="Real product image">
                        </div>
                    @endforeach
                </div>
            </div>
        </div>
    </div>
</div>
@endif
@endsection
@section('script')
@section('script')
<script>
$(document).ready(function() {

    // --- Modal Slider Initializations ---

    // Real Image Modal
    const realImageModal = document.getElementById('realImageModal');
    if (realImageModal) {
        realImageModal.addEventListener('shown.bs.modal', function () {
            const slider = $('#real-image-slider');
            if (!slider.hasClass('slick-initialized')) {
                slider.slick({
                    dots: true,
                    infinite: true,
                    speed: 300,
                    slidesToShow: 1,
                    adaptiveHeight: true,
                    arrows: true // Arrows are enabled
                });
            }
        });
    }

    // --- MODIFICATION FOR MAIN IMAGE POPUP ---
    let mainSliderClickedIndex = 0; // Global var to store which slide was clicked
    const mainImageModal = document.getElementById('mainImageModal');

    if (mainImageModal) {
        const modalSlider = $('#main-image-modal-slider');

        // When the modal is fully shown, INIT the slider
        mainImageModal.addEventListener('shown.bs.modal', function () {
            modalSlider.slick({
                dots: true,
                infinite: true,
                speed: 300,
                slidesToShow: 1,
                adaptiveHeight: true,
                arrows: true
            });
            // Go to the slide the user clicked on
            modalSlider.slick('slickGoTo', mainSliderClickedIndex);
        });

        // When the modal is fully hidden, DESTROY the slider
        mainImageModal.addEventListener('hidden.bs.modal', function () {
            modalSlider.slick('unslick');
        });
    }
    // --- END OF MODIFICATION ---


    // NEW: Click handler for the main product slider
    $('#main-product-slider').on('click', '.slick-slide', function() {
        mainSliderClickedIndex = $(this).data('slick-index');
        $('#mainImageModal').modal('show');
    });


    // --- Real-Time "People Watching" Counter ---
    const watchingContainer = $('.d-flex[data-product-id]');
    const watchingCountElement = $('#watching-count');

    if (watchingContainer.length && watchingCountElement.length) {
        const productId = watchingContainer.data('product-id');
        
        // Create a URL template using the named route and a placeholder
        const urlTemplate = "{{ route('product.view_count', ['id' => ':id']) }}";

        // Set an interval to check for new counts every 8 seconds
        setInterval(function() {
            // Replace the placeholder with the actual product ID for each request
            const finalUrl = urlTemplate.replace(':id', productId);

            $.ajax({
                url: finalUrl, // Use the generated URL
                type: 'GET',
                success: function(response) {
                    if (response.success) {
                        watchingCountElement.text(response.view_count);
                    }
                },
                error: function() {
                    console.log('Could not fetch new view count.');
                }
            });
        }, 8000); // Check every 8 seconds
    }
    // --- Configuration ---
    const BASE_PRODUCT_PRICE = {{ $product->discount_price ?? $product->base_price }};
    const IMAGE_BASE_URL = "{{ $front_ins_url . 'public/uploads/' }}";
    let selectedVariantId = null;
    let selectedSize = null;
    let currentStock = 0;
    
    // --- Slick Slider Initialization ---
    function initializeSlick() {
        // Destroy existing sliders if they exist
        if ($('#main-product-slider').hasClass('slick-initialized')) {
            $('#main-product-slider').slick('unslick');
        }
        if ($('#thumbnail-nav-slider').hasClass('slick-initialized')) {
            $('#thumbnail-nav-slider').slick('unslick');
        }

        $('#main-product-slider').slick({
            slidesToShow: 1,
            slidesToScroll: 1,
            arrows: false,
            fade: true,
            asNavFor: '#thumbnail-nav-slider'
        });

        $('#thumbnail-nav-slider').slick({
            slidesToShow: 3,
            slidesToScroll: 1,
            vertical: true,
            asNavFor: '#main-product-slider',
            dots: false,
            arrows: false,
            focusOnSelect: true
            /*
            responsive: [{
                breakpoint: 768,
                settings: {
                    slidesToShow: 4,
                    vertical: false
                }
            }]
            */
        });
    }

    // Custom arrow functionality
    $('.prev-arrow').click(() => $('#thumbnail-nav-slider').slick('slickPrev'));
    $('.next-arrow').click(() => $('#thumbnail-nav-slider').slick('slickNext'));

    // --- Core Logic Functions ---
    function updateSizes(sizes) {
        const container = $('#size-options-container');
        container.empty(); // Clear old sizes
        $('#selected-size-name').text('Select a size');
        selectedSize = null;
        currentStock = 0;

        if (sizes && sizes.length > 0) {
            sizes.forEach(size => {
                const button = $('<button></button>')
                    .addClass('btn btn-outline-secondary rounded-3 size-option')
                    .text(size.name)
                    .data('size-name', size.name)
                    .data('stock', size.quantity);
                
                if (size.quantity <= 0) {
                    button.prop('disabled', true);
                }
                container.append(button);
            });
        } else {
            container.html('<p class="text-danger small">This color is currently out of stock.</p>');
        }
    }

    // UPDATED: This function now updates the main slider AND the new modal slider
    function updateImages(mainImages, thumbImages) {
        const mainSlider = $('#main-product-slider');
        const thumbSlider = $('#thumbnail-nav-slider');
        const modalSlider = $('#main-image-modal-slider'); // NEW: Get the modal slider

        // NEW: Destroy the modal slider so it can be rebuilt
        if (modalSlider.hasClass('slick-initialized')) {
            modalSlider.slick('unslick');
        }
        
        mainSlider.empty();
        thumbSlider.empty();
        modalSlider.empty(); // NEW: Empty the modal slider too

        mainImages.forEach(img => {
            const mainSlideHTML = `<div><img src="${IMAGE_BASE_URL}${img}" class="img-fluid rounded-3"></div>`;
            const modalSlideHTML = `<div><img src="${IMAGE_BASE_URL}${img}" alt="{{ $product->name }}"></div>`;

            mainSlider.append(mainSlideHTML);
            modalSlider.append(modalSlideHTML); // NEW: Add image to modal slider
        });

        thumbImages.forEach(img => {
            thumbSlider.append(`<div><img src="${IMAGE_BASE_URL}${img}" class="img-fluid rounded-3 thumbnail-image"></div>`);
        });

        initializeSlick(); // This re-initializes the *page* sliders
        // The modal slider will be initialized if/when it is opened
    }
    
    function updatePrice(additionalPrice) {
        const finalPrice = BASE_PRODUCT_PRICE + parseFloat(additionalPrice || 0);
        $('#product-price').text(`৳ ${finalPrice.toFixed(2)}`);
    }

    // --- Event Handlers ---
    $('.color-option').on('click', function() {
        const $this = $(this);

        // Update active state
        $('.color-option').removeClass('active');
        $this.addClass('active');

        // Extract data
        const variantData = $this.data();
        selectedVariantId = variantData.variantId;
        
        // Update UI
        $('#selected-color-name').text(variantData.colorName);
        $('#product-sku').text(variantData.variantSku || '{{ $product->product_code }}');
        updateSizes(variantData.sizes);
        updatePrice(variantData.additionalPrice);
        updateImages(variantData.mainImages, variantData.thumbImages);
        $('#quantity-value').text(1);
    });

    $('#size-options-container').on('click', '.size-option:not(:disabled)', function() {
        const $this = $(this);
        $('#size-options-container .size-option').removeClass('active');
        $this.addClass('active');
        selectedSize = $this.data('size-name');
         currentStock = $this.data('stock');
        $('#selected-size-name').text(selectedSize);
        $('#quantity-value').text(1);
    });

    $('#quantity-plus').on('click', () => {
    // First, check if a size has been selected at all
    if (!selectedSize) {
        Swal.fire({
            icon: 'warning',
            title: 'Select a Size',
            text: 'Please select a size first.'
        });
        return;
    }

    let qty = parseInt($('#quantity-value').text());

    // Now, check if the quantity is already at the stock limit
    if (qty >= currentStock) {
        Swal.fire({
            icon: 'info',
            title: 'Stock Limit Reached',
            text: `Only ${currentStock} items are available for this size.`
        });
    } else {
        // Only increase the quantity if it's less than the stock
        $('#quantity-value').text(++qty);
    }
});

    $('#quantity-minus').on('click', () => {
        let qty = parseInt($('#quantity-value').text());
        if (qty > 1) {
            $('#quantity-value').text(--qty);
        }
    });

    $('#add-to-cart').on('click', function() {
        // Validation

         if (!selectedVariantId) {
            Swal.fire({
              icon: 'warning',
              title: 'Hold on!',
              text: 'Please select a color.'
            });
            return;
        }
        if (!selectedSize) {
            Swal.fire({
              icon: 'warning',
              title: 'Almost there!',
              text: 'Please select a size.'
            });
            return;
        }
        
        const $button = $(this);
        const cartData = {
            productId: {{ $product->id }},
            variantId: selectedVariantId,
            size: selectedSize,
            quantity: parseInt($('#quantity-value').text()),
            _token: "{{ csrf_token() }}" 
        };

        // AJAX call to add the product to the cart
        $.ajax({
            url: '{{ route("cart.add") }}',
            type: 'POST',
            data: cartData,
            beforeSend: function() {
                // Provide visual feedback
                $button.prop('disabled', true).html('<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span> Adding...');
            },
            success: function(response) {
                if (response.success) {
                    // Update the cart display everywhere
                    updateCartOffcanvas();
                    
                    // Automatically open the cart offcanvas to show the user their new item
                    const cartOffcanvas = new bootstrap.Offcanvas(document.getElementById('cartOffcanvas'));
                    cartOffcanvas.show();
                } else {
                    Swal.fire({
                      icon: 'error',
                      title: 'Oops...',
                      text: response.message || 'An unknown error occurred.'
                    });
                }
            },
            error: function(xhr) {
                let errorMessage = 'Something went wrong. Please try again.';
                if (xhr.responseJSON && xhr.responseJSON.message) {
                    errorMessage = xhr.responseJSON.message;
                }
                Swal.fire({
                  icon: 'error',
                  title: 'Request Failed',
                  text: errorMessage
                });
            },
            complete: function() {
                // Restore the button to its original state
                $button.prop('disabled', false).html('Add To Cart');
            }
        });
    });

     // --- NEW SEPARATE "Buy Now" Handler ---
    $('#buy-now').on('click', function() {
        if (!selectedVariantId) {
            Swal.fire({ icon: 'warning', title: 'Hold on!', text: 'Please select a color.' });
            return;
        }
        if (!selectedSize) {
            Swal.fire({ icon: 'warning', title: 'Almost there!', text: 'Please select a size.' });
            return;
        }

        const $button = $(this);
        const cartData = {
            productId: {{ $product->id }},
            variantId: selectedVariantId,
            size: selectedSize,
            quantity: parseInt($('#quantity-value').text()),
            _token: "{{ csrf_token() }}"
        };

        $.ajax({
            url: '{{ route("cart.add") }}',
            type: 'POST',
            data: cartData,
            beforeSend: function() {
                $button.prop('disabled', true).html('<span class="spinner-border spinner-border-sm"></span> Processing...');
            },
            success: function(response) {
                if (response.success) {
                    updateCartOffcanvas();
                    
                     @auth
                        // If user is logged in, redirect straight to checkout
                        window.location.href = "{{ route('user.checkout') }}";
                    @else
                        // If user is a guest, open the login/register offcanvas
                        const signInOffcanvas = new bootstrap.Offcanvas(document.getElementById('signInOffcanvas'));
                        signInOffcanvas.show();
                    @endauth
                } else {
                    Swal.fire({ icon: 'error', title: 'Oops...', text: response.message || 'An error occurred.' });
                }
            },
            error: function() {
                Swal.fire({ icon: 'error', title: 'Request Failed', text: 'Something went wrong.' });
            },
            complete: function() {
                // Only re-enable the button if the user is a guest (and the modal is shown)
                // Otherwise, the page will redirect.
                @guest
                    $button.prop('disabled', false).html('Buy Now');
                @endguest
            }
        });
    });

    // --- NEW: Handle Add to Wishlist on Product Detail Page ---
    $('#add-to-wishlist').on('click', function() {
        @auth
            // --- USER IS LOGGED IN ---
            if (!selectedVariantId) {
                Swal.fire({ icon: 'warning', title: 'Hold on!', text: 'Please select a color first.' });
                return;
            }
            if (!selectedSize) {
                Swal.fire({ icon: 'warning', title: 'Almost there!', text: 'Please select a size.' });
                return;
            }

            const $button = $(this);
            const wishlistData = {
                product_id: {{ $product->id }},
                variant_id: selectedVariantId,
                size: selectedSize,
                _token: "{{ csrf_token() }}"
            };

            $.ajax({
                url: '{{ route("wishlist.add") }}',
                type: 'POST',
                data: wishlistData,
                beforeSend: function() {
                    $button.prop('disabled', true).find('span').text('Adding...');
                },
                success: function(response) {
    if (response.success) {
        Swal.fire({
            toast: true,
            position: 'top-end',
            icon: 'success',
            title: response.message,
            showConfirmButton: false,
            timer: 2000
        });
        // UPDATE THE COUNT
        if(response.count !== undefined) {
            $('#wishlist-count').text(response.count);
            $('#mobile-wishlist-count').text(response.count);
        }
    } else {
         Swal.fire({ icon: 'info', title: 'Already Added', text: response.message });
    }
},
                error: function(xhr) {
                     Swal.fire({ icon: 'error', title: 'Oops...', text: 'Something went wrong. Please try again.' });
                },
                complete: function() {
                    $button.prop('disabled', false).find('span').text('Add to wishlist');
                }
            });

        @else
            // --- USER IS A GUEST ---
            Swal.fire({
                title: 'Login Required',
                text: "You need to be logged in to add items to your wishlist.",
                icon: 'info',
                showCancelButton: true,
                confirmButtonText: 'Login or Register',
                cancelButtonText: 'Not Now'
            }).then((result) => {

                 if (result.isConfirmed) {
                    // --- START OF NEW, MORE ROBUST FIX ---
                    const quickViewModalEl = document.getElementById('quickViewModal');
                    const quickViewModalInstance = bootstrap.Modal.getInstance(quickViewModalEl);
                    const signInOffcanvas = new bootstrap.Offcanvas(document.getElementById('signInOffcanvas'));

                    // 1. Hide the quick view modal
                    if (quickViewModalInstance) {
                        quickViewModalInstance.hide();
                    }

                    // 2. Manually remove the backdrop and cleanup body styles.
                    //    This forcefully resets the state and prevents conflicts.
                    $('.modal-backdrop').remove();
                    $('body').removeAttr('style').removeClass('modal-open');
                    
                    // 3. Show the sign-in offcanvas.
                    signInOffcanvas.show();
                    // --- END OF NEW FIX ---
                }
               
            });
        @endauth
    });

    // --- NEW: Add to Compare Handler ---
    $('#add-to-compare').on('click', function() {
        const productId = {{ $product->id }};
        const button = $(this);
        button.prop('disabled', true).find('span').text('Adding...');

        $.ajax({
            url: '{{ route("compare.add") }}',
            method: 'POST',
            data: { _token: '{{ csrf_token() }}', product_id: productId },
            success: function(response) {
                Swal.fire({ toast: true, position: 'top-end', icon: response.success ? 'success' : 'info', title: response.message, showConfirmButton: false, timer: 2500 });
                if(response.count !== undefined) {
                    $('#compare-count').text(response.count);
                }
            },
            error: function() {
                Swal.fire({icon: 'error', title: 'Error', text: 'Could not add to compare list.'});
            },
            complete: function() {
                button.prop('disabled', false).find('span').text('Add to compare');
            }
        });
    });

    // --- Initial Page Load ---
    initializeSlick();
    // Trigger a click on the first color to initialize sizes and prices
    $('.color-option.active').first().trigger('click');
});
</script>
@endsection