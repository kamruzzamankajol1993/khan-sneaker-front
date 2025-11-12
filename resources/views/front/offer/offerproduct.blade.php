@extends('front.master.master')

@section('title')
{{ $bundleDeal->title ?? 'Bundle Offer' }}
@endsection
@section('css')
<style>
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
    /* Real Image Modal Slider Style */
#realImageModal .modal-body {
    padding: 0.5rem; /* স্লাইডারের চারপাশে প্যাডিং যোগ করে */
}

.real-image-slider .slick-slide img {
    width: 100%;
    max-height: 75vh; /* ছবিটি যেন স্ক্রিনের চেয়ে বড় না হয় */
    object-fit: contain; /* সম্পূর্ণ ছবিটি দেখানোর জন্য */
    margin: auto;
}

/* মোডালের জন্য স্লাইডারের অ্যারো বাটন স্টাইল */
.real-image-slider .slick-prev,
.real-image-slider .slick-next {
    z-index: 10;
    width: 40px;
    height: 40px;
}
.real-image-slider .slick-prev { left: 25px; }
.real-image-slider .slick-next { right: 25px; }

.real-image-slider .slick-prev:before,
.real-image-slider .slick-next:before {
    font-size: 30px;
    opacity: .75;
    color: #333;
}
    .star-rating .bi-star-fill { color: #ffc107; }
    .review-images-container img { width: 70px; height: 70px; object-fit: cover; border-radius: 5px; cursor: pointer; margin-right: 5px;}
</style>
@endsection
@section('body')
<section class="section">
            <div class="container">
                <div class="spotlight_combo_page_product_container container my-5 p-4 bg-white rounded-4 shadow">

                    <!-- Product Page Header -->
                    <div class="d-flex align-items-center text-muted small mb-4">
                <span><a href="{{ route('home.index') }}" class="text-muted text-decoration-none">Home</a></span>
                <span class="mx-2">/</span>
                <span><a href="{{ route('offer.show', $bundleDeal->bundleOffer->name) }}" class="text-muted text-decoration-none">{{ $bundleDeal->bundleOffer->name }}</a></span>
                <span class="mx-2">/</span>
                <span class="fw-semibold text-dark">{{ $bundleDeal->title }}</span>
            </div>

                    <div class="row g-4">
                        <!-- Left Side: Image Gallery -->
                       <div class="col-12 col-lg-6">
    {{-- START: New wrapper for image gallery --}}
    <div class="d-flex">
        <div class="d-flex flex-column align-items-center">
            <div id="thumbnail-nav-slider" class="w-100 spotlight_combo_page_thumbnail_nav" style="max-width: 100px;">
                @forelse ($allImages as $image)
                <div>
                    <img src="{{ $front_ins_url .'public/uploads/' . $image }}"
                         alt="{{ $bundleDeal->title }} thumbnail"
                         class="img-fluid rounded-3 spotlight_combo_page_thumbnail_image">
                </div>
                @empty
                <div>
                    <img src="https://placehold.co/100x100/F5F5F5/4B5563?text=No+Image"
                         alt="No Image available"
                         class="img-fluid rounded-3 spotlight_combo_page_thumbnail_image">
                </div>
                @endforelse
            </div>
            @if (count($allImages) > 3)
            <div class="spotlight_combo_page_custom_arrows d-flex justify-content-start align-items-center w-100 mt-2">
                <button class="prev-arrow"><i class="bi bi-chevron-up"></i></button>
                <button class="next-arrow"><i class="bi bi-chevron-down"></i></button>
            </div>
            @endif
        </div>

        <div id="main-product-slider" class="flex-grow-1 rounded-3 overflow-hidden ms-4">
             @forelse ($allImages as $image)
            <div>
                <img src="{{ $front_ins_url .'public/uploads/' . $image }}"
                     alt="{{ $bundleDeal->title }} main image" class="img-fluid rounded-3">
            </div>
            @empty
            <div>
                <img src="https://placehold.co/1000x1000/F5F5F5/4B5563?text=No+Image+Available"
                     alt="No Image available" class="img-fluid rounded-3">
            </div>
            @endforelse
        </div>
    </div>
    {{-- END: New wrapper for image gallery --}}

    {{-- START: DYNAMIC "PEOPLE WATCHING" FEATURE --}}
    <div class="d-flex align-items-center justify-content-center bg-light p-3 rounded-3 mt-3" data-bundle-id="{{ $bundleDeal->id }}">
        <i class="bi bi-eye text-muted me-2"></i>
        <span class="small text-muted">
            <span id="watching-count" class="fw-bold">{{ $bundleDeal->view_count }}</span> People watching this product now!
        </span>
    </div>
    {{-- END: DYNAMIC "PEOPLE WATCHING" FEATURE --}}
</div>

                        <!-- Right Side: Product Details -->
                        <div class="col-12 col-lg-6 d-flex flex-column p-4 spotlight_combo_page_product_details">
                            <div class="d-flex flex-wrap align-items-center justify-content-between mb-2">
    <h1 class="h3 fw-semibold text-dark mb-0">{{ $bundleDeal->title }}</h1>

    {{-- `$allImages` অ্যারেতে ছবি থাকলেই শুধু বাটনটি দেখানো হবে --}}
    @if (!empty($allImages))
        <button class="btn btn-sm btn-outline-dark fw-semibold" data-bs-toggle="modal" data-bs-target="#realImageModal">
            <i class="bi bi-camera me-1"></i>
            Real Image
        </button>
    @endif
</div>
                    <p class="h6 text-muted mb-4">SKU: BDL-{{ $bundleDeal->id }}</p>
                    <div class="d-flex align-items-baseline mb-4">
                         @if($bundleDeal->discount_price > 0 && $bundleDeal->discount_price < $totalBasePrice)
                            <del class="text-muted h4 me-2" style="font-weight: 100 !important;">৳ {{ number_format($totalBasePrice) }}</del>
                            <span class="h3 fw-bold text-dark">৳ {{ number_format($bundleDeal->discount_price) }}</span>
                        @else
                            <span class="h3 fw-bold text-dark">৳ {{ number_format($totalBasePrice) }}</span>
                        @endif
                    </div>
                            <!-- Product Selection Boxes -->
<div class="row g-2 mb-4">
    @for ($i = 0; $i < $bundleDeal->buy_quantity; $i++)
    <div class="col-6">
        {{-- This button needs a unique ID and a data attribute to track its slot --}}
        <button
            id="select-btn-slot-{{ $i }}"
            class="btn btn-outline-secondary w-100 p-2 spotlight_combo_page_select-button"
            data-bs-toggle="modal"
            data-bs-target="#productSelectModal"
            data-slot-index="{{ $i }}">
            {{-- This inner div is what gets replaced by the script --}}
            <div class="d-flex flex-column align-items-center justify-content-center py-3">
                <i class="bi bi-plus-lg fs-4 mb-2"></i>
                <span class="small">Please select product {{ $i + 1 }}</span>
            </div>
        </button>
    </div>
    @endfor
</div>
                            <div id="selected-products-list-container" class="vstack gap-2 mb-4">
    @for ($i = 0; $i < $bundleDeal->buy_quantity; $i++)
        <div id="selected-item-slot-{{ $i }}" class="d-flex justify-content-between align-items-center py-2 ">
            
            {{-- The <a> tag now wraps both the text and the icon --}}
            <a href="#" class="text-muted text-decoration-none change-product-btn d-flex align-items-center" 
               data-bs-toggle="modal" 
               data-bs-target="#productSelectModal" 
               data-slot-index="{{ $i }}">
                <span class="me-2">Please select your product!</span>
                <i class="bi bi-pencil-square"></i>
            </a>

            {{-- Right side: Price placeholder --}}
            <div class="text-end text-muted">
                <span class="me-2">------</span>
                <span>------</span>
            </div>

        </div>
    @endfor
</div>

                            <hr class="my-4">

                            <!-- Combo Price Section -->
                            <div class="d-flex align-items-center mb-4">
                                <i class="bi bi-check-circle-fill text-success fs-5 me-2"></i>
                                <span class="fw-semibold">Please select a product for all items.</span>
                            </div>

                            <!-- Quantity and Buttons -->
                            <div class="d-flex flex-column flex-sm-row align-items-center gap-4 mb-4">
                                <div class="d-flex align-items-center border rounded-3 overflow-hidden quantity-selector">
    <button class="btn btn-light rounded-0 quantity-decrease">-</button>
    <span class="px-3 quantity-input">1</span>
    <button class="btn btn-light rounded-0 quantity-increase">+</button>
</div>
                                <button class="btn btn-dark fw-semibold rounded-3 flex-grow-1 add-to-cart-button">Add To
                                    Cart</button>
                                <button class="btn btn-secondary fw-semibold rounded-3 flex-grow-1 buy-button">Buy
                                    Now</button>
                            </div>

                            <!-- Actions and Share with Bootstrap Icons -->
                            <div class="d-flex flex-column flex-sm-row align-items-center justify-content-between mt-4">
                                <div class="d-flex align-items-center gap-2 mb-4 mb-sm-0">
    <a href="#" id="add-bundle-to-compare" class="btn btn-sm btn-outline-secondary d-flex align-items-center">
        <i class="bi bi-plus-circle me-2"></i>
        <span>Add to compare</span>
    </a>
    <a href="#" id="add-bundle-to-wishlist" class="btn btn-sm btn-outline-secondary d-flex align-items-center">
        <i class="bi bi-heart me-2"></i>
        <span>Add to wishlist</span>
    </a>
</div>
                                  @php
                                    $shareUrl = urlencode(url()->current());
                                    $shareTitle = urlencode($bundleDeal->title);
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

                            <!-- Section: People Watching and Delivery/Payment -->
                            <div class="mt-4 pt-4 border-top">
                                

                                <!-- Delivery Information -->
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

                                <!-- Payment Methods -->
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
    // Get the first main image from the bundle for the background, with a fallback.
    $reviewBgImage = !empty($allImages)
                   ? $front_ins_url . 'public/uploads/' . $allImages[0]
                   : ''; 
@endphp
        <section class="section" id="customer-reviews-section" style="background-image: url('{{ $reviewBgImage }}');">
        <div class="container">
            <h2 class="h5 fw-semibold mb-3">Description</h2>
            <div class="bg-white p-4 rounded-3 border">
               {{-- You can add a description to your bundle deal model if needed --}}
               <p>Enjoy a special discount with this exclusive bundle offer. Select from a variety of high-quality products to create your perfect package.</p>
            </div>

            <h2 class="h5 fw-semibold mt-5 mb-3">Customer Reviews</h2>
            <div class="row g-4">
                @php
                    // Aggregate review data from all products in the bundle
                    $allReviews = $productsCollection->pluck('reviews')->flatten();
                    $totalReviewsCount = $productsCollection->sum('reviews_count');
                    $averageRatingSum = $productsCollection->sum(function($product) {
                        return $product->reviews_avg_rating * $product->reviews_count;
                    });
                    $overallAverageRating = ($totalReviewsCount > 0) ? round($averageRatingSum / $totalReviewsCount, 1) : 0;
                @endphp
                <div class="col-12 col-lg-5 p-4 rounded-3 border bg-white">
                    @if($totalReviewsCount > 0)
                    <div class="text-center mb-4">
                        <div class="star-rating fs-3 mb-2">
                            @for ($i = 1; $i <= 5; $i++)
                                <i class="bi {{ $i <= round($overallAverageRating) ? 'bi-star-fill text-warning' : 'bi-star text-muted' }}"></i>
                            @endfor
                        </div>
                        <p class="text-muted">{{ $totalReviewsCount }} {{ Str::plural('review', $totalReviewsCount) }} in total for products in this bundle</p>
                        <p class="mt-4 small fw-semibold">Overall Rating: {{ $overallAverageRating }}/5.0</p>
                    </div>
                    @php
                        $ratingCounts = $allReviews->groupBy('rating')->map->count();
                        $ratingPercentages = [];
                        for ($i = 5; $i >= 1; $i--) {
                            $count = $ratingCounts->get($i, 0);
                            $percentage = ($totalReviewsCount > 0) ? ($count / $totalReviewsCount) * 100 : 0;
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
                        @if($totalReviewsCount > 0)
            <p class="text-muted">{{ $totalReviewsCount }} {{ Str::plural('review', $totalReviewsCount) }} in total for products in this bundle</p>
            <p class="mt-4 small fw-semibold">Overall Rating: {{ number_format($overallAverageRating, 1) }}/5.0</p>
        @else
            <p class="text-muted mt-2">There are no reviews yet for the products in this bundle.</p>
            <p class="small">Be the first to leave a review after your purchase!</p>
        @endif
                    </div>
                    @endif
                </div>

                <div class="col-12 col-lg-7">
                    @forelse($allReviews->sortByDesc('created_at') as $review)
                    <div class="bg-white p-3 rounded-3 border mb-3">
                        <div class="d-flex align-items-start">
                            <img src="{{ optional($review->user)->image ? asset('public/'.optional($review->user)->image) : 'https://placehold.co/50x50' }}" alt="{{ optional($review->user)->name }}" class="rounded-circle" style="width: 50px; height: 50px;">
                            <div class="ms-3">
                                <h6 class="mb-0">{{ optional($review->user)->name ?? 'Anonymous' }}</h6>
                                <div class="star-rating text-muted small">
                                    @for ($i = 1; $i <= 5; $i++)
                                        <i class="bi {{ $i <= $review->rating ? 'bi-star-fill text-warning' : 'bi-star text-muted' }}"></i>
                                    @endfor
                                    <span class="ms-2">{{ \Carbon\Carbon::parse($review->created_at)->diffForHumans() }}</span>
                                </div>
                                <p class="mt-1 mb-0 small fst-italic">Reviewed: <a href="{{ route('product.show', $review->product->slug) }}" class="text-decoration-none">{{ $review->product->name }}</a></p>
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
        <!-- Modal for Product Selection -->
    <div class="modal fade" id="productSelectModal" tabindex="-1" aria-labelledby="productSelectModalLabel" aria-hidden="true">
    <div class="modal-dialog modal-dialog-centered modal-lg">
        <div class="modal-content spotlight_combo_page_modal-card">
            <div class="modal-header border-0 pb-0">
                <button type="button" class="btn btn-sm btn-link me-2" id="modal-back-btn" style="display: none;">
                    <i class="bi bi-arrow-left"></i> Back
                </button>
                <h5 class="modal-title fw-semibold" id="productSelectModalLabel">PLEASE SELECT YOUR PRODUCT</h5>
                <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
            </div>
            <div class="modal-body">
                <div id="modal-product-view">
                    <div class="row row-cols-2 row-cols-md-4 g-3">
                        @forelse ($productsCollection as $product)
                        <div class="col">
                            <div class="card h-100 initial-product-option" style="cursor: pointer;" data-product-id="{{ $product->id }}">
                                <img src="{{ (is_array($product->main_image) && count($product->main_image) > 0) ? $front_ins_url .'public/uploads/' . $product->main_image[0] : 'https://placehold.co/300x300' }}" 
                                     alt="{{ $product->name }}" class="card-img-top">
                                <div class="card-body text-center p-2">
                                    <h6 class="card-title small">{{ $product->name }}</h6>
                                    {{-- START: ADDED PRICE DISPLAY --}}
                    @php
                        // Calculate the discounted per-item price for the bundle
                        $discountedPricePerItem = $bundleDeal->discount_price / $bundleDeal->buy_quantity;
                    @endphp
                    <p class="card-text small">
                        <del class="text-muted me-1">৳ {{ number_format($product->base_price, 1) }}</del>
                        <span class="fw-bold">৳ {{ number_format($discountedPricePerItem, 1) }}</span>
                    </p>
                    {{-- END: ADDED PRICE DISPLAY --}}
                                </div>
                            </div>
                        </div>
                        @empty
                        <div class="col-12"><p class="text-center">No products found.</p></div>
                        @endforelse
                    </div>
                </div>

                <div id="modal-variant-view" style="display: none;">
                    </div>
            </div>
        </div>
    </div>
</div>

{{-- Real Image Viewer Modal --}}
@if (!empty($allImages))
<div class="modal fade" id="realImageModal" tabindex="-1" aria-labelledby="realImageModalLabel" aria-hidden="true">
    <div class="modal-dialog modal-dialog-centered modal-xl">
        <div class="modal-content">
            <div class="modal-header">
                <h5 class="modal-title" id="realImageModalLabel">{{ $bundleDeal->title }} - Images</h5>
                <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
            </div>
            <div class="modal-body">
                <div id="real-image-slider" class="real-image-slider">
                    @foreach($allImages as $image)
                        <div>
                            <img src="{{ $front_ins_url .'public/uploads/' . $image }}" alt="Real bundle image">
                        </div>
                    @endforeach
                </div>
            </div>
        </div>
    </div>
</div>
@endif
@endsection
<script id="products-with-variants-data" type="application/json">
    @json($productsCollection->keyBy('id'))
</script>
@section('script')
<script src="https://cdn.jsdelivr.net/npm/sweetalert2@11"></script>
<script>
    
    $(document).ready(function(){

        // --- Real Image Modal Slider Initialization ---
const realImageModal = document.getElementById('realImageModal');
if (realImageModal) {
    realImageModal.addEventListener('shown.bs.modal', function () {
        const slider = $('#real-image-slider');
        
        // স্লাইডারটি আগে থেকে চালু না থাকলে তবেই চালু করবে
        if (!slider.hasClass('slick-initialized')) {
            slider.slick({
                dots: true,
                infinite: true,
                speed: 300,
                slidesToShow: 1,
                adaptiveHeight: true,
                arrows: true
            });
        }
    });
}

       // --- Real-Time "People Watching" Counter for Bundle ---
const watchingContainer = $('.d-flex[data-bundle-id]');
const watchingCountElement = $('#watching-count');

if (watchingContainer.length && watchingCountElement.length) {
    const bundleId = watchingContainer.data('bundle-id');
    const urlTemplate = "{{ route('bundle.view_count', ['id' => ':id']) }}";

    setInterval(function() {
        const finalUrl = urlTemplate.replace(':id', bundleId);
        $.ajax({
            url: finalUrl,
            type: 'GET',
            success: function(response) {
                if (response.success) {
                    watchingCountElement.text(response.view_count);
                }
            },
            error: function() {
                console.log('Could not fetch new bundle view count.');
            }
        });
    }, 9000); // প্রতি ৯ সেকেন্ড পর পর চেক করবে
}
        // 1. Initialize the Slick sliders for the main product image gallery
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
            focusOnSelect: true,
            responsive: [
                {
                    breakpoint: 992,
                    settings: {
                        vertical: false,
                        slidesToShow: 4
                    }
                }
            ]
        });
        
        $('.prev-arrow').click(function(){
            $('#thumbnail-nav-slider').slick('slickPrev');
        });

        $('.next-arrow').click(function(){
            $('#thumbnail-nav-slider').slick('slickNext');
        });

                // --- START: SCRIPT FOR TWO-STEP BUNDLE SELECTION MODAL ---

        const productsData = JSON.parse(document.getElementById('products-with-variants-data').textContent);
        const modalEl = document.getElementById('productSelectModal');
        const modal = new bootstrap.Modal(modalEl);
        const modalTitle = $('#productSelectModalLabel');
        const productView = $('#modal-product-view');
        const variantView = $('#modal-variant-view');
        const backBtn = $('#modal-back-btn');
       


        let selectedProducts = {};
        let currentSlotIndex = null;
        const initialModalTitle = modalTitle.text();

        $(document).on('click', '.spotlight_combo_page_select-button, .change-product-btn', function() {
            currentSlotIndex = $(this).data('slot-index');
        });

        $(document).on('click', '.initial-product-option', function() {
            const productId = $(this).data('productId');
            const product = productsData[productId];
            let variantHTML = '<div class="row row-cols-2 row-cols-md-3 g-3">';
            product.variants.forEach(variant => {
                variant.detailed_sizes.forEach(sizeInfo => {
                    const imagePath = (variant.variant_image && variant.variant_image.length > 0)
                        ? variant.variant_image[0]
                        : (product.main_image && product.main_image.length > 0 ? product.main_image[0] : null);
                    const variantImage = imagePath ? `{{ $front_ins_url . 'public/uploads/' }}${imagePath}` : 'https://placehold.co/300x300';

                    const basePrice = parseFloat(product.base_price) + parseFloat(variant.additional_price || 0);
                    const discountedPrice = {{ $bundleDeal->discount_price / $bundleDeal->buy_quantity }};

                    variantHTML += `
                        <div class="col">
                            <div class="card h-100 final-variant-option" style="cursor: pointer;"
                                 data-product-id="${product.id}" data-variant-id="${variant.id}" data-size-name="${sizeInfo.name}"
                                 data-product-name="${product.name}" data-color-name="${variant.color ? variant.color.name : ''}"
                                 data-base-price="${basePrice}" data-final-price="${discountedPrice}" data-product-image="${variantImage}">
                                <img src="${variantImage}" class="card-img-top" alt="${product.name}">
                                <div class="card-body text-center p-2">
                                    <h6 class="card-title small mb-1">${product.name}</h6>
                                    <p class="card-text small mb-1">Size: ${sizeInfo.name}</p>
                                    <p class="card-text small">
                                        <del class="text-muted me-1">৳ ${basePrice.toFixed(1)}</del>
                                        <span class="fw-bold">৳ ${discountedPrice.toFixed(1)}</span>
                                    </p>
                                </div>
                            </div>
                        </div>`;
                });
            });
            variantHTML += '</div>';
            modalTitle.text(product.name);
            variantView.html(variantHTML).show();
            productView.hide();
            backBtn.show();
        });

        $(document).on('click', '.final-variant-option', function() {
            const productData = {
                id: $(this).data('productId'),
                variantId: $(this).data('variantId'),
                name: $(this).data('productName'),
                basePrice: parseFloat($(this).data('basePrice')),
                finalPrice: parseFloat($(this).data('finalPrice')),
                image: $(this).data('productImage'),
                size: $(this).data('sizeName'),
                color: $(this).data('colorName')
            };

            selectedProducts[currentSlotIndex] = productData;
            // THIS IS THE KEY FUNCTION CALL
            updateSelectionUI(currentSlotIndex, productData);
            updateSelectedItemSlot(currentSlotIndex, productData);
            modal.hide();
        });

        backBtn.on('click', function() {
            modalTitle.text(initialModalTitle);
            productView.show();
            variantView.hide();
            backBtn.hide();
        });

        modalEl.addEventListener('hidden.bs.modal', function (event) {
            modalTitle.text(initialModalTitle);
            productView.show();
            variantView.hide().html('');
            backBtn.hide();
        });

        /**
         * THIS IS THE FUNCTION THAT UPDATES THE BUTTON'S APPEARANCE
         */
        function updateSelectionUI(slotIndex, product) {
            const button = $(`#select-btn-slot-${slotIndex}`);
            const buttonContent = `
                <div class="d-flex align-items-center p-1 text-start">
                    <img src="${product.image}" alt="${product.name}" style="width: 50px; height: 50px; object-fit: cover;" class="rounded me-2">
                    <div>
                        <span class="small d-block fw-bold">${product.name}</span>
                        <span class="small d-block text-muted">Size: ${product.size}</span>
                    </div>
                </div>
            `;
            button.removeClass('btn-outline-secondary').addClass('btn-light');
            button.html(buttonContent);
        }

        /**
         * This function updates the list below the buttons.
         */
        function updateSelectedItemSlot(slotIndex, product) {
            const slotElement = $(`#selected-item-slot-${slotIndex}`);
            if (slotElement.length === 0) return;
            const updatedHTML = `
                <a href="#" class="text-muted text-decoration-none change-product-btn d-flex align-items-center"
                   data-bs-toggle="modal" data-bs-target="#productSelectModal" data-slot-index="${slotIndex}">
                    <span class="me-2">${product.name} Size: ${product.size}</span>
                    <i class="bi bi-pencil-square"></i>
                </a>
                <div class="text-end">
                    <del class="text-muted me-2">৳ ${product.basePrice.toFixed(1)}</del>
                    <span class="fw-bold">৳ ${product.finalPrice.toFixed(1)}</span>
                </div>
            `;
            const parentDiv = slotElement.empty().addClass('d-flex justify-content-between align-items-center py-2 border-bottom');
            parentDiv.html(updatedHTML);
        }

        // --- START: Quantity Selector Logic ---
        $('.quantity-decrease').on('click', function() {
            let quantityInput = $(this).siblings('.quantity-input');
            let currentQuantity = parseInt(quantityInput.text());
            if (currentQuantity > 1) {
                quantityInput.text(currentQuantity - 1);
            }
        });

        $('.quantity-increase').on('click', function() {
            let quantityInput = $(this).siblings('.quantity-input');
            let currentQuantity = parseInt(quantityInput.text());
            quantityInput.text(currentQuantity + 1);
        });
        // --- END: Quantity Selector Logic ---


        // --- START: SCRIPT FOR ADDING BUNDLE TO CART ---
        $('.add-to-cart-button').on('click', function() {
            const buyQuantity = {{ $bundleDeal->buy_quantity }};
            const selectedCount = Object.keys(selectedProducts).length;

            // 1. Validate: Check if all slots are filled
            if (selectedCount < buyQuantity) {
               Swal.fire({
                  icon: 'warning',
                  title: 'Incomplete Selection',
                  text: 'Please select a product for all available slots before adding to cart.'
                });
                return; // Stop the function
            }
            
            const button = $(this);
            button.prop('disabled', true).text('Adding...');

            // 2. Prepare Payload
            const selectedProductsArray = Object.values(selectedProducts);
            const payload = {
                _token: '{{ csrf_token() }}',
                bundleId: {{ $bundleDeal->id }},
                quantity: parseInt($('.quantity-input').text()),
                selectedProducts: selectedProductsArray
            };

            // 3. AJAX Request
            $.ajax({
                url: '{{ route("cart.addBundle") }}',
                type: 'POST',
                data: JSON.stringify(payload),
                contentType: 'application/json',
                success: function(response) {
                    if (response.success) {
    // Show a success notification toast
    Swal.fire({
        toast: true,
        position: 'top-end',
        icon: 'success',
        title: response.message,
        showConfirmButton: false,
        timer: 3000,
        timerProgressBar: true
    });

    // Call a function to update the mini-cart display
    // Make sure this function is defined in your global JS file
    updateCartOffcanvas(); 
    
} else {
    // Show an error popup
    Swal.fire({
        icon: 'error',
        title: 'Request Failed',
        text: 'An unknown error occurred. Please try again.'
    });
}
                },
                error: function(xhr) {
                    let errorMessage = 'Could not add bundle to cart. Please try again.';
                    if (xhr.responseJSON && xhr.responseJSON.message) {
                        errorMessage = xhr.responseJSON.message;
                    }
                    Swal.fire({
                      icon: 'error',
                      title: 'Oops...',
                      text: errorMessage
                    });
                },
                complete: function() {
                     button.prop('disabled', false).text('Add To Cart');
                }
            });
        });
        // --- END: SCRIPT FOR ADDING BUNDLE TO CART ---


         // --- START: SCRIPT FOR ADDING BUNDLE TO CART ---
        $('.buy-button').on('click', function() {
            const buyQuantity = {{ $bundleDeal->buy_quantity }};
            const selectedCount = Object.keys(selectedProducts).length;

            // 1. Validate: Check if all slots are filled
            if (selectedCount < buyQuantity) {
               Swal.fire({
                  icon: 'warning',
                  title: 'Incomplete Selection',
                  text: 'Please select a product for all available slots before adding to cart.'
                });
                return; // Stop the function
            }
            
            const button = $(this);
            button.prop('disabled', true).text('Adding...');

            // 2. Prepare Payload
            const selectedProductsArray = Object.values(selectedProducts);
            const payload = {
                _token: '{{ csrf_token() }}',
                bundleId: {{ $bundleDeal->id }},
                quantity: parseInt($('.quantity-input').text()),
                selectedProducts: selectedProductsArray
            };

            // 3. AJAX Request
            $.ajax({
                url: '{{ route("cart.addBundle") }}',
                type: 'POST',
                data: JSON.stringify(payload),
                contentType: 'application/json',
                success: function(response) {
                    if (response.success) {
    // Show a success notification toast
    Swal.fire({
        toast: true,
        position: 'top-end',
        icon: 'success',
        title: response.message,
        showConfirmButton: false,
        timer: 3000,
        timerProgressBar: true
    });

    // Call a function to update the mini-cart display
    // Make sure this function is defined in your global JS file
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
    // Show an error popup
    Swal.fire({
        icon: 'error',
        title: 'Request Failed',
        text: 'An unknown error occurred. Please try again.'
    });
}
                },
                error: function(xhr) {
                    let errorMessage = 'Could not add bundle to cart. Please try again.';
                    if (xhr.responseJSON && xhr.responseJSON.message) {
                        errorMessage = xhr.responseJSON.message;
                    }
                    Swal.fire({
                      icon: 'error',
                      title: 'Oops...',
                      text: errorMessage
                    });
                },
                complete: function() {
                     button.prop('disabled', false).text('Add To Cart');
                }
            });
        });
        // --- END: SCRIPT FOR ADDING BUNDLE TO CART ---

        // --- NEW SCRIPT FOR ADDING BUNDLE TO WISHLIST ---
    $('#add-bundle-to-wishlist').on('click', function() {
        @auth
            // --- USER IS LOGGED IN ---
            const buyQuantity = {{ $bundleDeal->buy_quantity }};
            const selectedCount = Object.keys(selectedProducts).length;

            if (selectedCount < buyQuantity) {
                Swal.fire({ icon: 'warning', title: 'Incomplete Selection', text: 'Please select a product for all available slots first.' });
                return;
            }

            const $button = $(this);
            const payload = {
                selected_products: Object.values(selectedProducts),
                _token: "{{ csrf_token() }}"
            };

            $.ajax({
                url: '{{ route("wishlist.addBundle") }}',
                type: 'POST',
                data: payload,
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
            timer: 3000
        });

        // --- ADD THESE LINES TO UPDATE THE COUNTERS ---
        if (response.count !== undefined) {
            $('#wishlist-count').text(response.count);
            $('#mobile-wishlist-count').text(response.count);
        }
        // --- END OF NEW LINES ---
    }
},
                error: function(xhr) {
                    Swal.fire({ icon: 'error', title: 'Oops...', text: xhr.responseJSON.message || 'Something went wrong.' });
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


      // --- SCRIPT FOR ADDING BUNDLE TO COMPARE ---
    $('#add-bundle-to-compare').on('click', function() {
        const buyQuantity = {{ $bundleDeal->buy_quantity }};
        const selectedCount = Object.keys(selectedProducts).length;

        if (selectedCount < buyQuantity) {
            Swal.fire({ icon: 'warning', title: 'Incomplete Selection', text: 'Please select a product for all available slots first.' });
            return;
        }

        const button = $(this);
        button.prop('disabled', true).find('span').text('Adding...');
        
        // Collect all unique selected product IDs
        const productIds = [...new Set(Object.values(selectedProducts).map(p => p.id))];

        $.ajax({
            url: '{{ route("compare.addMultiple") }}',
            method: 'POST',
            data: {
                _token: '{{ csrf_token() }}',
                product_ids: productIds
            },
            success: function(response) {
                Swal.fire({
                    toast: true,
                    position: 'top-end',
                    icon: response.success ? 'success' : 'info',
                    title: response.message,
                    showConfirmButton: false,
                    timer: 2500
                });
                
                if(response.count !== undefined) {
                    $('#compare-count').text(response.count); // Update the count in the header
                }
            },
            error: function(xhr) {
                Swal.fire({icon: 'error', title: 'Error', text: xhr.responseJSON.message || 'Could not add to compare list.'});
            },
            complete: function() {
                button.prop('disabled', false).find('span').text('Add to compare');
            }
        });
    });

    });

</script>
@endsection