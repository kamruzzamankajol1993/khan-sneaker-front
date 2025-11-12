@extends('front.master.master')

@section('title', 'Home')
@section('css')
<style>
   /* --- START: FINAL PRODUCT CARD STYLES --- */

/* Make the entire product card interactive */
.product-card {
    transition: box-shadow 0.3s ease;
    position: relative;
    overflow: hidden;
}

/* Add a shadow when the card is hovered on desktop */
.product-card:hover {
    box-shadow: 0 8px 25px rgba(0, 0, 0, 0.1);
    z-index: 15;
}

.product-image-container {
    position: relative;
    display: block;
}

.product-image-container picture img {
    transition: transform 0.3s ease-in-out;
}

.product-image-hover {
    position: absolute;
    top: 0;
    left: 0;
    opacity: 0;
    transition: opacity 0.3s ease-in-out;
    z-index: 5;
}

/* --- DESKTOP STYLES FOR ACTION BUTTONS --- */
/* The buttons are now positioned relative to the whole card */
.product-actions {
    position: absolute;
    top: 35%; /* Adjust this % to perfectly center on your images */
    left: 50%;
    z-index: 10;
    display: flex;
    gap: 10px;
    
    /* Start centered, smaller, and invisible */
    opacity: 0;
    transform: translate(-50%, -50%) scale(0.9);
    transition: opacity 0.3s ease, transform 0.3s ease, visibility 0.3s;
    visibility: hidden; /* Hide completely */
}

/* Styling for the individual circle buttons */
.product-action-btn {
    display: flex;
    justify-content: center;
    align-items: center;
    width: 40px;
    height: 40px;
    background-color: #ffffff;
    color: #333;
    border-radius: 50%;
    box-shadow: 0 2px 8px rgba(0,0,0,0.15);
    transition: background-color 0.2s, color 0.2s, transform 0.2s ease;
    text-decoration: none;
}

.product-action-btn:hover {
    background-color: #0d6efd;
    color: #ffffff;
    transform: translateY(-2px);
}

/* Animate buttons to appear on card hover */
.product-card:hover .product-actions {
    opacity: 1;
    transform: translate(-50%, -50%) scale(1);
    visibility: visible; /* Make them visible */
}

/* Other hover effects */
.product-card:hover .product-image-hover {
    opacity: 1;
}
.product-card:hover .product-image-container picture img {
    transform: scale(1.05);
}

/* --- START: FINAL MOBILE RESPONSIVE STYLES --- */
@media (max-width: 767.98px) {

    /* The container for the buttons on mobile */
    .product-actions {
        position: static;
        visibility: visible;
        opacity: 1;
        transform: none;
        display: flex;
        justify-content: center;
        gap: 2px; /* Increased gap for better touch separation */
        margin-top: 10px;
        margin-bottom: 16px;
    }

    /* The "Perfect Circle" buttons */
    .product-action-btn {
        /* 1. Precise Shape & Sizing */
        width: 35px;
        height: 35px;
        min-width: 35px; /* Prevents squashing */
        border-radius: 50%; /* Guarantees a circle */
        border: none; /* No border */
        
        /* 2. Premium Aesthetics */
        background-color: #ffffff;
        /* A softer, more realistic shadow */
        box-shadow: 0 4px 8px rgba(0, 0, 0, 0.08), 0 1px 3px rgba(0, 0, 0, 0.06);
        
        /* 3. Perfect Icon Centering */
        display: flex;
        align-items: center;
        justify-content: center;
        
        /* 4. Smooth Interaction */
        transition: all 0.2s ease-out;
    }
    
    /* Provides visual feedback when a button is tapped */
    .product-action-btn:active {
        transform: scale(0.94);
        box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
    }
    
    /* Icon Styling */
    .product-action-btn i {
        font-size: 1.1rem; /* Slightly larger, more prominent icon */
        color: #343a40;
        line-height: 1; /* Critical for preventing alignment shifts */
    }

    /* Disable desktop-only hover effects on mobile */
    .product-card:hover {
        box-shadow: none;
    }
    .product-card:hover .product-image-container picture img {
        transform: none;
    }
    .product-card:hover .product-image-hover {
        opacity: 0;
    }
}
/* --- END: FINAL MOBILE RESPONSIVE STYLES --- */
/* --- END: REFINED MOBILE RESPONSIVE STYLES --- */
</style>
<style>
    /* Container for the product images */
    .product-image-container {
        position: relative; /* Needed to position the hover image correctly */
        display: block;
        overflow: hidden; /* Ensures images stay within the card boundaries */
    }

    /* Styling for both default and hover images */
    .product-image-container picture img {
        transition: transform 0.3s ease-in-out; /* Optional: adds a slight zoom effect on hover */
    }

    /* The hover image is positioned directly on top of the default one */
  .product-image-hover {
    position: absolute;
    top: 0;
    left: 0;
    width: 100%; /* Ensure it covers the full area */
    height: 100%; /* Ensure it covers the full area */
    opacity: 0; /* It's completely invisible by default */
    transition: opacity 0.3s ease-in-out; /* This creates the smooth fade effect */
    z-index: 5; /* This places the hover image ABOVE the default image but BELOW the action buttons */
}

    /* When you hover over the container... */
    .product-image-container:hover .product-image-hover {
        opacity: 1; /* ...the hover image fades in and becomes visible */
    }
    
    /* Optional: Slight zoom effect on the image when hovering */
    .product-image-container:hover picture img {
        transform: scale(1.05);
    }
</style>
@endsection
@section('body')
    <main>
       <section class="spotlighthero hero-section">
    <div class="container-fluid">
        <div class="row">
            <div class="col-lg-12 mb-3 mb-lg-0">
                <div class="main-slider">
                    {{-- Check if any left sliders exist and are active --}}
                    @if(isset($heroLeftSliders) && $heroLeftSliders->count() > 0)
                        @foreach($heroLeftSliders as $slider)
                            <div class="slider-item">
                                @php
                                    // Determine the correct link for the polymorphic relationship
                                    $link = '#';
                                    if ($slider->linkable) {
                                        if ($slider->linkable_type === 'App\Models\Product') {
                                            $link = route('product.show', $slider->linkable->slug);
                                        } elseif ($slider->linkable_type === 'App\Models\Category') {
                                            $link = route('category.show', $slider->linkable->slug);
                                        } elseif ($slider->linkable_type === 'App\Models\BundleOffer') {
                                            $link = route('offer.show', $slider->linkable->slug);
                                        }
                                        // You can add more 'elseif' conditions here for other models
                                    }
                                @endphp
                                {{-- The entire image is now a clickable link --}}
                                <a href="{{ $link }}">
                                    <img src="{{ $front_ins_url . 'public/' . $slider->image }}" alt="{{ $slider->title }}">
                                </a>
                                <div class="content">
                                    <h1 class="fw-bold">{{ Str::upper($slider->title) }}</h1>
                                    <p>{{ $slider->subtitle }}</p>
                                    <a href="{{ $link }}" class="btn btn-outline-light">ORDER NOW</a>
                                </div>
                            </div>
                        @endforeach
                    @else
                        {{-- Fallback content if no sliders are set up in the admin panel --}}
                        <div class="slider-item">
                            <img src="https://placehold.co/847x537" alt="Default Banner">
                            <div class="content">
                                <h1 class="fw-bold">WELCOME</h1>
                                <p>Check out our latest collections.</p>
                                <a href="{{ route('shop.show') }}" class="btn btn-outline-light">SHOP NOW</a>
                            </div>
                        </div>
                    @endif
                </div>
            </div>

        
        </div>
    </div>
</section>
        {{-- This entire section will only show if the status is active and products are available --}}
@if(isset($topRatedTitle) && !empty($topRatedTitle) && $products->isNotEmpty())
<section class="section">
    <div class="product-section">
        <div class="container">
            {{-- The title is now dynamic based on your admin panel selection --}}
            <h2 class="mb-4 text-center">{{ Str::upper($topRatedTitle) }}</h2>
            <div class="product-slider">
                {{-- The loop remains the same, but it now uses the data fetched based on your settings --}}
                @foreach($products as $product)
                <div class="product-card card">
    @php
        // --- DEFAULT IMAGES (Image 1) ---
        $mobileImage = (is_array($product->thumbnail_image) && count($product->thumbnail_image) > 0)
                        ? $front_ins_url . 'public/uploads/' . $product->thumbnail_image[0]
                        : 'https://placehold.co/400x400';
        $desktopImage = (is_array($product->main_image) && count($product->main_image) > 0)
                        ? $front_ins_url . 'public/uploads/' . $product->main_image[0]
                        : 'https://placehold.co/400x400';

        // --- HOVER IMAGES (Image 2) ---
        // If the second image exists, use it. Otherwise, FALL BACK to the first image.
        $mobileImageHover = (is_array($product->thumbnail_image) && count($product->thumbnail_image) > 1)
                            ? $front_ins_url . 'public/uploads/' . $product->thumbnail_image[1]
                            : $mobileImage;
        $desktopImageHover = (is_array($product->main_image) && count($product->main_image) > 1)
                             ? $front_ins_url . 'public/uploads/' . $product->main_image[1]
                             : $desktopImage;

        // Calculate total stock
        $totalStock = 0;
        if ($product->variants->isNotEmpty()) {
            foreach ($product->variants as $variant) {
                if (is_array($variant->sizes)) {
                    foreach ($variant->sizes as $sizeInfo) {
                        $totalStock += $sizeInfo['quantity'] ?? 0;
                    }
                }
            }
        }
          $extraCategoryName = null;
        if ($product->assigns) { // Check if assigns relationship is loaded
            $extraCategoryAssignment = $product->assigns->where('type', 'other')->first();
            if ($extraCategoryAssignment) {
                $extraCategory = \App\Models\ExtraCategory::find($extraCategoryAssignment->category_id);
                if ($extraCategory) {
                    $extraCategoryName = $extraCategory->name;
                }
            }
        }
    @endphp

    {{-- The link is now the main container for the images --}}
    <a href="{{ route('product.show', $product->slug) }}" class="product-image-container">

         @if ($extraCategoryName)
            <span class="product-badge">{{ $extraCategoryName }}</span>
        @endif
        <picture class="product-image-default">
            <source media="(min-width: 992px)" srcset="{{ $desktopImage }}">
            <source media="(max-width: 991px)" srcset="{{ $mobileImage }}">
            <img src="{{ $mobileImage }}" 
                 alt="{{ $product->name }}" 
                 class="card-img-top img-fluid">
        </picture>

        <picture class="product-image-hover">
            <source media="(min-width: 992px)" srcset="{{ $desktopImageHover }}">
            <source media="(max-width: 991px)" srcset="{{ $mobileImageHover }}">
            <img src="{{ $mobileImageHover }}" 
                 alt="{{ $product->name }} hover" 
                 class="card-img-top img-fluid">
        </picture>
    </a>
   
    <div class="product-details-body">
        <h5 class="product-title mb-1"><a href="{{ route('product.show', $product->slug) }}">
                        {{ $product->name }}
                        </a></h5>
        <p class="product-meta mb-1">Category: {{ $product->productCategoryAssignment->category->name ?? 'N/A' }}</p>
        <p class="product-meta mb-1">SKU: {{ $product->product_code ?? 'N/A' }}</p>

        @if($totalStock > 0)
            <p class="product-meta text-success fw-bold mb-1"><i class="bi bi-check-circle-fill"></i> In stock</p>
        @else
            <p class="product-meta text-danger fw-bold mb-1"><i class="bi bi-x-circle-fill"></i> Out of stock</p>
        @endif

        <div class="rating-stars mb-2">
    @php
        // Round the average rating to the nearest whole number
        $rating = round($product->reviews_avg_rating ?? 0);
    @endphp
    @for ($i = 1; $i <= 5; $i++)
        @if ($i <= $rating)
            {{-- Show a filled star if the loop index is less than or equal to the rating --}}
            <i class="bi bi-star-fill"></i>
        @else
            {{-- Otherwise, show an empty star --}}
            <i class="bi bi-star"></i>
        @endif
    @endfor
</div>

        <p class="price-tag mb-2">
            @if($product->discount_price)
                <del class="text-muted" style="font-weight: 100 !important;">৳ {{ $product->base_price }}</del>
                <span class="fw-bold">৳ {{ $product->discount_price }}</span>
            @else
                <span class="fw-bold">৳ {{ $product->base_price }}</span>
            @endif
        </p>
 <div class="product-actions">
        <a href="#" class="product-action-btn btn-add-cart" data-product-id="{{ $product->id }}" data-bs-toggle="tooltip" title="Quick View">
            <i class="bi bi-eye"></i>
        </a>
        <a href="#" class="product-action-btn btn-add-cart" data-product-id="{{ $product->id }}" data-bs-toggle="tooltip" title="Add to Cart">
            <i class="bi bi-cart-plus"></i>
        </a>
        <a href="#" class="product-action-btn btn-add-cart" data-product-id="{{ $product->id }}" data-bs-toggle="tooltip" title="Add to Wishlist">
            <i class="bi bi-heart"></i>
        </a>
        <a href="#" class="product-action-btn btn-add-cart" data-product-id="{{ $product->id }}" data-bs-toggle="tooltip" title="Add to Compare">
            <i class="bi bi-arrow-left-right"></i>
        </a>
    </div>
    </div>
</div>
                @endforeach
            </div>
        </div>
    </div>
</section>
@else
<section class="section">
            <div class="product-section">
                <div class="container">
                    <h2 class="mb-4 text-center">Top Rated Products</h2>
                    <div class="product-slider">
                        <!-- Product Card 1 -->
                        <div class="product-card card">
                            <img src="https://placehold.co/300x300" class="card-img-top" alt="Product 1">
                            <div class="product-details-body">
                                <h5 class="product-title mb-1">Product Name 1</h5>
                                <p class="product-meta mb-1">Category: Men's Clothing</p>
                                <p class="product-meta mb-1">SKU: PN-001</p>
                                <p class="product-meta text-success fw-bold mb-1"><i
                                        class="bi bi-check-circle-fill"></i> In stock</p>
                                <div class="rating-stars mb-2">
                                    <i class="bi bi-star-fill"></i><i class="bi bi-star-fill"></i><i
                                        class="bi bi-star-fill"></i><i class="bi bi-star-fill"></i><i
                                        class="bi bi-star-half"></i>
                                </div>
                                <p class="price-tag mb-2">৳ 950.0</p>
                                <a href="#" class="btn btn-primary btn-add-cart">Add to Cart</a>
                            </div>
                        </div>
                        <!-- Product Card 2 -->
                        <div class="product-card card">
                            <img src="https://placehold.co/300x300" class="card-img-top" alt="Product 2">
                            <div class="product-details-body">
                                <h5 class="product-title mb-1">Product Name 2</h5>
                                <p class="product-meta mb-1">Category: Women's Wear</p>
                                <p class="product-meta mb-1">SKU: PN-002</p>
                                <p class="product-meta text-success fw-bold mb-1"><i
                                        class="bi bi-check-circle-fill"></i> In stock</p>
                                <div class="rating-stars mb-2">
                                    <i class="bi bi-star-fill"></i><i class="bi bi-star-fill"></i><i
                                        class="bi bi-star-fill"></i><i class="bi bi-star-fill"></i><i
                                        class="bi bi-star"></i>
                                </div>
                                <p class="price-tag mb-2">৳ 1200.0</p>
                                <a href="#" class="btn btn-primary btn-add-cart">Add to Cart</a>
                            </div>
                        </div>
                        <!-- Product Card 3 -->
                        <div class="product-card card">
                            <img src="https://placehold.co/300x300" class="card-img-top" alt="Product 3">
                            <div class="product-details-body">
                                <h5 class="product-title mb-1">Product Name 3</h5>
                                <p class="product-meta mb-1">Category: Accessories</p>
                                <p class="product-meta mb-1">SKU: PN-003</p>
                                <p class="product-meta text-success fw-bold mb-1"><i
                                        class="bi bi-check-circle-fill"></i> In stock</p>
                                <div class="rating-stars mb-2">
                                    <i class="bi bi-star-fill"></i><i class="bi bi-star-fill"></i><i
                                        class="bi bi-star-fill"></i><i class="bi bi-star-fill"></i><i
                                        class="bi bi-star-fill"></i>
                                </div>
                                <p class="price-tag mb-2">৳ 850.0</p>
                                <a href="#" class="btn btn-primary btn-add-cart">Add to Cart</a>
                            </div>
                        </div>
                        <!-- Product Card 4 -->
                        <div class="product-card card">
                            <img src="https://placehold.co/300x300" class="card-img-top" alt="Product 4">
                            <div class="product-details-body">
                                <h5 class="product-title mb-1">Product Name 4</h5>
                                <p class="product-meta mb-1">Category: Electronics</p>
                                <p class="product-meta mb-1">SKU: PN-004</p>
                                <p class="product-meta text-success fw-bold mb-1"><i
                                        class="bi bi-check-circle-fill"></i> In stock</p>
                                <div class="rating-stars mb-2">
                                    <i class="bi bi-star-fill"></i><i class="bi bi-star-fill"></i><i
                                        class="bi bi-star-fill"></i><i class="bi bi-star"></i><i class="bi bi-star"></i>
                                </div>
                                <p class="price-tag mb-2">৳ 1500.0</p>
                                <a href="#" class="btn btn-primary btn-add-cart">Add to Cart</a>
                            </div>
                        </div>
                        <!-- Product Card 5 -->
                        <div class="product-card card">
                            <img src="https://placehold.co/300x300" class="card-img-top" alt="Product 5">
                            <div class="product-details-body">
                                <h5 class="product-title mb-1">Product Name 5</h5>
                                <p class="product-meta mb-1">Category: Books</p>
                                <p class="product-meta mb-1">SKU: PN-005</p>
                                <p class="product-meta text-danger fw-bold mb-1"><i class="bi bi-x-circle-fill"></i> Out
                                    of stock</p>
                                <div class="rating-stars mb-2">
                                    <i class="bi bi-star-fill"></i><i class="bi bi-star-fill"></i><i
                                        class="bi bi-star"></i><i class="bi bi-star"></i><i class="bi bi-star"></i>
                                </div>
                                <p class="price-tag mb-2">৳ 750.0</p>
                                <a href="#" class="btn btn-primary btn-add-cart">Add to Cart</a>
                            </div>
                        </div>
                        <!-- Product Card 6 -->
                        <div class="product-card card">
                            <img src="https://placehold.co/300x300" class="card-img-top" alt="Product 6">
                            <div class="product-details-body">
                                <h5 class="product-title mb-1">Product Name 6</h5>
                                <p class="product-meta mb-1">Category: Home Goods</p>
                                <p class="product-meta mb-1">SKU: PN-006</p>
                                <p class="product-meta text-success fw-bold mb-1"><i
                                        class="bi bi-check-circle-fill"></i> In stock</p>
                                <div class="rating-stars mb-2">
                                    <i class="bi bi-star-fill"></i><i class="bi bi-star-fill"></i><i
                                        class="bi bi-star-fill"></i><i class="bi bi-star-fill"></i><i
                                        class="bi bi-star-fill"></i>
                                </div>
                                <p class="price-tag mb-2">৳ 1100.0</p>
                                <a href="#" class="btn btn-primary btn-add-cart">Add to Cart</a>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </section>
@endif
{{-- ADD THE NEW SECTION FOR THE SECOND ROW HERE --}}
@if(isset($secondRowTitle) && !empty($secondRowTitle) && $secondRowProducts->isNotEmpty())
<section class="section">
    <div class="product-section">
        <div class="container">
            {{-- The title is dynamic based on your admin panel selection for the second row --}}
            <h2 class="mb-4 text-center">{{ Str::upper($secondRowTitle) }}</h2>
            <div class="product-slider">
                @foreach($secondRowProducts as $product)
                <div class="product-card card">
    @php
        // --- DEFAULT IMAGES (Image 1) ---
        $mobileImage = (is_array($product->thumbnail_image) && count($product->thumbnail_image) > 0)
                        ? $front_ins_url . 'public/uploads/' . $product->thumbnail_image[0]
                        : 'https://placehold.co/400x400';
        $desktopImage = (is_array($product->main_image) && count($product->main_image) > 0)
                        ? $front_ins_url . 'public/uploads/' . $product->main_image[0]
                        : 'https://placehold.co/400x400';

        // --- HOVER IMAGES (Image 2) ---
        // If the second image exists, use it. Otherwise, FALL BACK to the first image.
        $mobileImageHover = (is_array($product->thumbnail_image) && count($product->thumbnail_image) > 1)
                            ? $front_ins_url . 'public/uploads/' . $product->thumbnail_image[1]
                            : $mobileImage;
        $desktopImageHover = (is_array($product->main_image) && count($product->main_image) > 1)
                             ? $front_ins_url . 'public/uploads/' . $product->main_image[1]
                             : $desktopImage;

        // Calculate total stock
        $totalStock = 0;
        if ($product->variants->isNotEmpty()) {
            foreach ($product->variants as $variant) {
                if (is_array($variant->sizes)) {
                    foreach ($variant->sizes as $sizeInfo) {
                        $totalStock += $sizeInfo['quantity'] ?? 0;
                    }
                }
            }
        }
          $extraCategoryName = null;
        if ($product->assigns) { // Check if assigns relationship is loaded
            $extraCategoryAssignment = $product->assigns->where('type', 'other')->first();
            if ($extraCategoryAssignment) {
                $extraCategory = \App\Models\ExtraCategory::find($extraCategoryAssignment->category_id);
                if ($extraCategory) {
                    $extraCategoryName = $extraCategory->name;
                }
            }
        }
    @endphp

    {{-- The link is now the main container for the images --}}
    <a href="{{ route('product.show', $product->slug) }}" class="product-image-container">
         @if ($extraCategoryName)
            <span class="product-badge">{{ $extraCategoryName }}</span>
        @endif
        <picture class="product-image-default">
            <source media="(min-width: 992px)" srcset="{{ $desktopImage }}">
            <source media="(max-width: 991px)" srcset="{{ $mobileImage }}">
            <img src="{{ $mobileImage }}" 
                 alt="{{ $product->name }}" 
                 class="card-img-top img-fluid">
        </picture>

        <picture class="product-image-hover">
            <source media="(min-width: 992px)" srcset="{{ $desktopImageHover }}">
            <source media="(max-width: 991px)" srcset="{{ $mobileImageHover }}">
            <img src="{{ $mobileImageHover }}" 
                 alt="{{ $product->name }} hover" 
                 class="card-img-top img-fluid">
        </picture>
    </a>

    <div class="product-details-body">
        <h5 class="product-title mb-1"><a href="{{ route('product.show', $product->slug) }}">
                        {{ $product->name }}
                        </a></h5>
        <p class="product-meta mb-1">Category: {{ $product->productCategoryAssignment->category->name ?? 'N/A' }}</p>
        <p class="product-meta mb-1">SKU: {{ $product->product_code ?? 'N/A' }}</p>

        @if($totalStock > 0)
            <p class="product-meta text-success fw-bold mb-1"><i class="bi bi-check-circle-fill"></i> In stock</p>
        @else
            <p class="product-meta text-danger fw-bold mb-1"><i class="bi bi-x-circle-fill"></i> Out of stock</p>
        @endif

        <div class="rating-stars mb-2">
    @php
        // Round the average rating to the nearest whole number
        $rating = round($product->reviews_avg_rating ?? 0);
    @endphp
    @for ($i = 1; $i <= 5; $i++)
        @if ($i <= $rating)
            {{-- Show a filled star if the loop index is less than or equal to the rating --}}
            <i class="bi bi-star-fill"></i>
        @else
            {{-- Otherwise, show an empty star --}}
            <i class="bi bi-star"></i>
        @endif
    @endfor
</div>

        <p class="price-tag mb-2">
            @if($product->discount_price)
                <del class="text-muted" style="font-weight: 100 !important;">৳ {{ $product->base_price }}</del>
                <span class="fw-bold">৳ {{ $product->discount_price }}</span>
            @else
                <span class="fw-bold">৳ {{ $product->base_price }}</span>
            @endif
        </p>
<div class="product-actions">
        <a href="#" class="product-action-btn btn-add-cart" data-product-id="{{ $product->id }}" data-bs-toggle="tooltip" title="Quick View">
            <i class="bi bi-eye"></i>
        </a>
        <a href="#" class="product-action-btn btn-add-cart" data-product-id="{{ $product->id }}" data-bs-toggle="tooltip" title="Add to Cart">
            <i class="bi bi-cart-plus"></i>
        </a>
        <a href="#" class="product-action-btn btn-add-cart" data-product-id="{{ $product->id }}" data-bs-toggle="tooltip" title="Add to Wishlist">
            <i class="bi bi-heart"></i>
        </a>
        <a href="#" class="product-action-btn btn-add-cart" data-product-id="{{ $product->id }}" data-bs-toggle="tooltip" title="Add to Compare">
            <i class="bi bi-arrow-left-right"></i>
        </a>
    </div>
    </div>
</div>
                @endforeach
            </div>
        </div>
    </div>
</section>
@endif
{{-- Continue with the rest of your homepage sections --}}
       @if($homepageRow1 && $homepageRow1->category)
       @if(count($row1Products) > 0)
<section>
    <div class="featured-product-section">
        <div class="container">
            <div class="row">
                <div class="col-lg-4 mb-4 mb-lg-0 d-flex">
                    <div class="featured-banner flex-grow-1">
                        <img src="{{ $front_ins_url .$homepageRow1->image }}" alt="{{ $homepageRow1->title ?? $homepageRow1->category->name }}">
                        <div class="content">
                            <h4 class="mb-3">{!! nl2br(e($homepageRow1->title)) !!}</h4>
                            <p class="mb-4">"Explore our {{ $homepageRow1->category->name }} collection"</p>
                            <a href="{{ route('category.show', $homepageRow1->category->slug) }}" class="btn btn-outline-light">Buy Now</a>
                        </div>
                    </div>
                </div>
                <div class="col-lg-8">
                    <h2 class="mb-4 text-center">{{ Str::upper($homepageRow1->category->name) }}</h2>
                    <div class="product-carousel">
                        @forelse($row1Products as $product)
                            <div class="product-card card">
    @php
        // --- DEFAULT IMAGES (Image 1) ---
        $mobileImage = (is_array($product->thumbnail_image) && count($product->thumbnail_image) > 0)
                        ? $front_ins_url . 'public/uploads/' . $product->thumbnail_image[0]
                        : 'https://placehold.co/400x400';
        $desktopImage = (is_array($product->main_image) && count($product->main_image) > 0)
                        ? $front_ins_url . 'public/uploads/' . $product->main_image[0]
                        : 'https://placehold.co/400x400';

        // --- HOVER IMAGES (Image 2) ---
        // If the second image exists, use it. Otherwise, FALL BACK to the first image.
        $mobileImageHover = (is_array($product->thumbnail_image) && count($product->thumbnail_image) > 1)
                            ? $front_ins_url . 'public/uploads/' . $product->thumbnail_image[1]
                            : $mobileImage;
        $desktopImageHover = (is_array($product->main_image) && count($product->main_image) > 1)
                             ? $front_ins_url . 'public/uploads/' . $product->main_image[1]
                             : $desktopImage;

        // Calculate total stock
        $totalStock = 0;
        if ($product->variants->isNotEmpty()) {
            foreach ($product->variants as $variant) {
                if (is_array($variant->sizes)) {
                    foreach ($variant->sizes as $sizeInfo) {
                        $totalStock += $sizeInfo['quantity'] ?? 0;
                    }
                }
            }
        }
          $extraCategoryName = null;
        if ($product->assigns) { // Check if assigns relationship is loaded
            $extraCategoryAssignment = $product->assigns->where('type', 'other')->first();
            if ($extraCategoryAssignment) {
                $extraCategory = \App\Models\ExtraCategory::find($extraCategoryAssignment->category_id);
                if ($extraCategory) {
                    $extraCategoryName = $extraCategory->name;
                }
            }
        }
    @endphp

    {{-- The link is now the main container for the images --}}
    <a href="{{ route('product.show', $product->slug) }}" class="product-image-container">
         @if ($extraCategoryName)
            <span class="product-badge">{{ $extraCategoryName }}</span>
        @endif
        <picture class="product-image-default">
            <source media="(min-width: 992px)" srcset="{{ $desktopImage }}">
            <source media="(max-width: 991px)" srcset="{{ $mobileImage }}">
            <img src="{{ $mobileImage }}" 
                 alt="{{ $product->name }}" 
                 class="card-img-top img-fluid">
        </picture>

        <picture class="product-image-hover">
            <source media="(min-width: 992px)" srcset="{{ $desktopImageHover }}">
            <source media="(max-width: 991px)" srcset="{{ $mobileImageHover }}">
            <img src="{{ $mobileImageHover }}" 
                 alt="{{ $product->name }} hover" 
                 class="card-img-top img-fluid">
        </picture>
    </a>
   
    <div class="product-details-body">
        <h5 class="product-title mb-1"><a href="{{ route('product.show', $product->slug) }}">
                        {{ $product->name }}
                        </a></h5>
        <p class="product-meta mb-1">Category: {{ $product->productCategoryAssignment->category->name ?? 'N/A' }}</p>
        <p class="product-meta mb-1">SKU: {{ $product->product_code ?? 'N/A' }}</p>

        @if($totalStock > 0)
            <p class="product-meta text-success fw-bold mb-1"><i class="bi bi-check-circle-fill"></i> In stock</p>
        @else
            <p class="product-meta text-danger fw-bold mb-1"><i class="bi bi-x-circle-fill"></i> Out of stock</p>
        @endif

        <div class="rating-stars mb-2">
    @php
        // Round the average rating to the nearest whole number
        $rating = round($product->reviews_avg_rating ?? 0);
    @endphp
    @for ($i = 1; $i <= 5; $i++)
        @if ($i <= $rating)
            {{-- Show a filled star if the loop index is less than or equal to the rating --}}
            <i class="bi bi-star-fill"></i>
        @else
            {{-- Otherwise, show an empty star --}}
            <i class="bi bi-star"></i>
        @endif
    @endfor
</div>

        <p class="price-tag mb-2">
            @if($product->discount_price)
                <del class="text-muted" style="font-weight: 100 !important;">৳ {{ $product->base_price }}</del>
                <span class="fw-bold">৳ {{ $product->discount_price }}</span>
            @else
                <span class="fw-bold">৳ {{ $product->base_price }}</span>
            @endif
        </p>
 <div class="product-actions">
        <a href="#" class="product-action-btn btn-add-cart" data-product-id="{{ $product->id }}" data-bs-toggle="tooltip" title="Quick View">
            <i class="bi bi-eye"></i>
        </a>
        <a href="#" class="product-action-btn btn-add-cart" data-product-id="{{ $product->id }}" data-bs-toggle="tooltip" title="Add to Cart">
            <i class="bi bi-cart-plus"></i>
        </a>
        <a href="#" class="product-action-btn btn-add-cart" data-product-id="{{ $product->id }}" data-bs-toggle="tooltip" title="Add to Wishlist">
            <i class="bi bi-heart"></i>
        </a>
        <a href="#" class="product-action-btn btn-add-cart" data-product-id="{{ $product->id }}" data-bs-toggle="tooltip" title="Add to Compare">
            <i class="bi bi-arrow-left-right"></i>
        </a>
    </div>
    </div>
</div>
                        @empty
                            <p class="text-center w-100">No products found for this category.</p>
                        @endforelse
                    </div>
                </div>
            </div>
        </div>
    </div>
</section>
@else

 <section>
            <div class="featured-product-section">
                <div class="container">
                    <div class="row">
                        <!-- Left side: Banner -->
                        <div class="col-lg-4 mb-4 mb-lg-0 d-flex">
                            <div class="featured-banner flex-grow-1">
                                <img src="https://placehold.co/410x530" alt="Men's Premium T-Shirt">
                                <div class="content">
                                    <h4 class="mb-3">MEN'S PREMIUM<br>ACID WASH</h4>
                                    <p class="mb-4">"Itachi Uchiha <br>Retro vibes and faded dreams—this acid wash tee
                                        brings the vintage feels to your closet."</p>
                                    <a href="#" class="btn btn-outline-light">Buy Now</a>
                                </div>
                            </div>
                        </div>
                        <!-- Right side: Product Slider -->
                        <div class="col-lg-8">
                            <h2 class="mb-4 text-center">ALL COLLECTIONS</h2>
                            <div class="product-carousel">
                                <div class="product-card card">
                                    <img src="https://placehold.co/300x300" class="card-img-top" alt="Product 6">
                                    <div class="product-details-body">
                                        <h5 class="product-title mb-1">Product Name 6</h5>
                                        <p class="product-meta mb-1">Category: Home Goods</p>
                                        <p class="product-meta mb-1">SKU: PN-006</p>
                                        <p class="product-meta text-success fw-bold mb-1"><i
                                                class="bi bi-check-circle-fill"></i> In stock</p>
                                        <div class="rating-stars mb-2">
                                            <i class="bi bi-star-fill"></i><i class="bi bi-star-fill"></i><i
                                                class="bi bi-star-fill"></i><i class="bi bi-star-fill"></i><i
                                                class="bi bi-star-fill"></i>
                                        </div>
                                        <p class="price-tag mb-2">৳ 1100.0</p>
                                        <a href="#" class="btn btn-primary btn-add-cart">Add to Cart</a>
                                    </div>
                                </div>
                                <div class="product-card card">
                                    <img src="https://placehold.co/300x300" class="card-img-top" alt="Product 6">
                                    <div class="product-details-body">
                                        <h5 class="product-title mb-1">Product Name 6</h5>
                                        <p class="product-meta mb-1">Category: Home Goods</p>
                                        <p class="product-meta mb-1">SKU: PN-006</p>
                                        <p class="product-meta text-success fw-bold mb-1"><i
                                                class="bi bi-check-circle-fill"></i> In stock</p>
                                        <div class="rating-stars mb-2">
                                            <i class="bi bi-star-fill"></i><i class="bi bi-star-fill"></i><i
                                                class="bi bi-star-fill"></i><i class="bi bi-star-fill"></i><i
                                                class="bi bi-star-fill"></i>
                                        </div>
                                        <p class="price-tag mb-2">৳ 1100.0</p>
                                        <a href="#" class="btn btn-primary btn-add-cart">Add to Cart</a>
                                    </div>
                                </div>
                                <div class="product-card card">
                                    <img src="https://placehold.co/300x300" class="card-img-top" alt="Product 6">
                                    <div class="product-details-body">
                                        <h5 class="product-title mb-1">Product Name 6</h5>
                                        <p class="product-meta mb-1">Category: Home Goods</p>
                                        <p class="product-meta mb-1">SKU: PN-006</p>
                                        <p class="product-meta text-success fw-bold mb-1"><i
                                                class="bi bi-check-circle-fill"></i> In stock</p>
                                        <div class="rating-stars mb-2">
                                            <i class="bi bi-star-fill"></i><i class="bi bi-star-fill"></i><i
                                                class="bi bi-star-fill"></i><i class="bi bi-star-fill"></i><i
                                                class="bi bi-star-fill"></i>
                                        </div>
                                        <p class="price-tag mb-2">৳ 1100.0</p>
                                        <a href="#" class="btn btn-primary btn-add-cart">Add to Cart</a>
                                    </div>
                                </div>
                                <div class="product-card card">
                                    <img src="https://placehold.co/300x300" class="card-img-top" alt="Product 6">
                                    <div class="product-details-body">
                                        <h5 class="product-title mb-1">Product Name 6</h5>
                                        <p class="product-meta mb-1">Category: Home Goods</p>
                                        <p class="product-meta mb-1">SKU: PN-006</p>
                                        <p class="product-meta text-success fw-bold mb-1"><i
                                                class="bi bi-check-circle-fill"></i> In stock</p>
                                        <div class="rating-stars mb-2">
                                            <i class="bi bi-star-fill"></i><i class="bi bi-star-fill"></i><i
                                                class="bi bi-star-fill"></i><i class="bi bi-star-fill"></i><i
                                                class="bi bi-star-fill"></i>
                                        </div>
                                        <p class="price-tag mb-2">৳ 1100.0</p>
                                        <a href="#" class="btn btn-primary btn-add-cart">Add to Cart</a>
                                    </div>
                                </div>
                                <div class="product-card card">
                                    <img src="https://placehold.co/300x300" class="card-img-top" alt="Product 6">
                                    <div class="product-details-body">
                                        <h5 class="product-title mb-1">Product Name 6</h5>
                                        <p class="product-meta mb-1">Category: Home Goods</p>
                                        <p class="product-meta mb-1">SKU: PN-006</p>
                                        <p class="product-meta text-success fw-bold mb-1"><i
                                                class="bi bi-check-circle-fill"></i> In stock</p>
                                        <div class="rating-stars mb-2">
                                            <i class="bi bi-star-fill"></i><i class="bi bi-star-fill"></i><i
                                                class="bi bi-star-fill"></i><i class="bi bi-star-fill"></i><i
                                                class="bi bi-star-fill"></i>
                                        </div>
                                        <p class="price-tag mb-2">৳ 1100.0</p>
                                        <a href="#" class="btn btn-primary btn-add-cart">Add to Cart</a>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </section>

@endif
@endif
       {{-- This section is now powered by the Homepage Section settings for Row 2 --}}
@if($homepageRow2 && $homepageRow2->category)
 @if(count($row2Products) > 0)
<section>
    <div class="featured-product-section">
        <div class="container">
            <div class="row">
                <div class="col-lg-4 mb-4 mb-lg-0 d-flex">
                    <div class="featured-banner flex-grow-1">
                        <img src="{{ $front_ins_url .$homepageRow2->image }}" alt="{{ $homepageRow2->title ?? $homepageRow2->category->name }}">
                        <div class="content">
                            <h4 class="mb-3">{!! nl2br(e($homepageRow2->title)) !!}</h4>
                            <p class="mb-4">"Discover our {{ $homepageRow2->category->name }} selection"</p>
                            <a href="{{ route('category.show', $homepageRow2->category->slug) }}" class="btn btn-outline-light">Buy Now</a>
                        </div>
                    </div>
                </div>
                <div class="col-lg-8">
                    <h2 class="mb-4 text-center">{{ Str::upper($homepageRow2->category->name) }}</h2>
                    <div class="product-carousel">
                        @forelse($row2Products as $product)
                            <div class="product-card card">
    @php
        // --- DEFAULT IMAGES (Image 1) ---
        $mobileImage = (is_array($product->thumbnail_image) && count($product->thumbnail_image) > 0)
                        ? $front_ins_url . 'public/uploads/' . $product->thumbnail_image[0]
                        : 'https://placehold.co/400x400';
        $desktopImage = (is_array($product->main_image) && count($product->main_image) > 0)
                        ? $front_ins_url . 'public/uploads/' . $product->main_image[0]
                        : 'https://placehold.co/400x400';

        // --- HOVER IMAGES (Image 2) ---
        // If the second image exists, use it. Otherwise, FALL BACK to the first image.
        $mobileImageHover = (is_array($product->thumbnail_image) && count($product->thumbnail_image) > 1)
                            ? $front_ins_url . 'public/uploads/' . $product->thumbnail_image[1]
                            : $mobileImage;
        $desktopImageHover = (is_array($product->main_image) && count($product->main_image) > 1)
                             ? $front_ins_url . 'public/uploads/' . $product->main_image[1]
                             : $desktopImage;

        // Calculate total stock
        $totalStock = 0;
        if ($product->variants->isNotEmpty()) {
            foreach ($product->variants as $variant) {
                if (is_array($variant->sizes)) {
                    foreach ($variant->sizes as $sizeInfo) {
                        $totalStock += $sizeInfo['quantity'] ?? 0;
                    }
                }
            }
        }
    @endphp

    {{-- The link is now the main container for the images --}}
    <a href="{{ route('product.show', $product->slug) }}" class="product-image-container">
         @if ($extraCategoryName)
            <span class="product-badge">{{ $extraCategoryName }}</span>
        @endif
        <picture class="product-image-default">
            <source media="(min-width: 992px)" srcset="{{ $desktopImage }}">
            <source media="(max-width: 991px)" srcset="{{ $mobileImage }}">
            <img src="{{ $mobileImage }}" 
                 alt="{{ $product->name }}" 
                 class="card-img-top img-fluid">
        </picture>

        <picture class="product-image-hover">
            <source media="(min-width: 992px)" srcset="{{ $desktopImageHover }}">
            <source media="(max-width: 991px)" srcset="{{ $mobileImageHover }}">
            <img src="{{ $mobileImageHover }}" 
                 alt="{{ $product->name }} hover" 
                 class="card-img-top img-fluid">
        </picture>
    </a>
    
    <div class="product-details-body">
        <h5 class="product-title mb-1"><a href="{{ route('product.show', $product->slug) }}">
                        {{ $product->name }}
                        </a></h5>
        <p class="product-meta mb-1">Category: {{ $product->productCategoryAssignment->category->name ?? 'N/A' }}</p>
        <p class="product-meta mb-1">SKU: {{ $product->product_code ?? 'N/A' }}</p>

        @if($totalStock > 0)
            <p class="product-meta text-success fw-bold mb-1"><i class="bi bi-check-circle-fill"></i> In stock</p>
        @else
            <p class="product-meta text-danger fw-bold mb-1"><i class="bi bi-x-circle-fill"></i> Out of stock</p>
        @endif

        <div class="rating-stars mb-2">
    @php
        // Round the average rating to the nearest whole number
        $rating = round($product->reviews_avg_rating ?? 0);
    @endphp
    @for ($i = 1; $i <= 5; $i++)
        @if ($i <= $rating)
            {{-- Show a filled star if the loop index is less than or equal to the rating --}}
            <i class="bi bi-star-fill"></i>
        @else
            {{-- Otherwise, show an empty star --}}
            <i class="bi bi-star"></i>
        @endif
    @endfor
</div>

        <p class="price-tag mb-2">
            @if($product->discount_price)
                <del class="text-muted" style="font-weight: 100 !important;">৳ {{ $product->base_price }}</del>
                <span class="fw-bold">৳ {{ $product->discount_price }}</span>
            @else
                <span class="fw-bold">৳ {{ $product->base_price }}</span>
            @endif
        </p>
<div class="product-actions">
        <a href="#" class="product-action-btn btn-add-cart" data-product-id="{{ $product->id }}" data-bs-toggle="tooltip" title="Quick View">
            <i class="bi bi-eye"></i>
        </a>
        <a href="#" class="product-action-btn btn-add-cart" data-product-id="{{ $product->id }}" data-bs-toggle="tooltip" title="Add to Cart">
            <i class="bi bi-cart-plus"></i>
        </a>
        <a href="#" class="product-action-btn btn-add-cart" data-product-id="{{ $product->id }}" data-bs-toggle="tooltip" title="Add to Wishlist">
            <i class="bi bi-heart"></i>
        </a>
        <a href="#" class="product-action-btn btn-add-cart" data-product-id="{{ $product->id }}" data-bs-toggle="tooltip" title="Add to Compare">
            <i class="bi bi-arrow-left-right"></i>
        </a>
    </div>
    </div>
</div>
                        @empty
                            <p class="text-center w-100">No products found for this category.</p>
                        @endforelse
                    </div>
                </div>
            </div>
        </div>
    </div>
</section>
@else

 <section>
            <div class="featured-product-section">
                <div class="container">
                    <div class="row">
                        <!-- Left side: Banner -->
                        <div class="col-lg-4 mb-4 mb-lg-0 d-flex">
                            <div class="featured-banner flex-grow-1">
                                <img src="https://placehold.co/410x530" alt="Men's Premium T-Shirt">
                                <div class="content">
                                    <h4 class="mb-3">MEN'S PREMIUM<br>ACID WASH</h4>
                                    <p class="mb-4">"Itachi Uchiha <br>Retro vibes and faded dreams—this acid wash tee
                                        brings the vintage feels to your closet."</p>
                                    <a href="#" class="btn btn-outline-light">Buy Now</a>
                                </div>
                            </div>
                        </div>
                        <!-- Right side: Product Slider -->
                        <div class="col-lg-8">
                            <h2 class="mb-4 text-center">ALL COLLECTIONS</h2>
                            <div class="product-carousel">
                                <div class="product-card card">
                                    <img src="https://placehold.co/300x300" class="card-img-top" alt="Product 6">
                                    <div class="product-details-body">
                                        <h5 class="product-title mb-1">Product Name 6</h5>
                                        <p class="product-meta mb-1">Category: Home Goods</p>
                                        <p class="product-meta mb-1">SKU: PN-006</p>
                                        <p class="product-meta text-success fw-bold mb-1"><i
                                                class="bi bi-check-circle-fill"></i> In stock</p>
                                        <div class="rating-stars mb-2">
                                            <i class="bi bi-star-fill"></i><i class="bi bi-star-fill"></i><i
                                                class="bi bi-star-fill"></i><i class="bi bi-star-fill"></i><i
                                                class="bi bi-star-fill"></i>
                                        </div>
                                        <p class="price-tag mb-2">৳ 1100.0</p>
                                        <a href="#" class="btn btn-primary btn-add-cart">Add to Cart</a>
                                    </div>
                                </div>
                                <div class="product-card card">
                                    <img src="https://placehold.co/300x300" class="card-img-top" alt="Product 6">
                                    <div class="product-details-body">
                                        <h5 class="product-title mb-1">Product Name 6</h5>
                                        <p class="product-meta mb-1">Category: Home Goods</p>
                                        <p class="product-meta mb-1">SKU: PN-006</p>
                                        <p class="product-meta text-success fw-bold mb-1"><i
                                                class="bi bi-check-circle-fill"></i> In stock</p>
                                        <div class="rating-stars mb-2">
                                            <i class="bi bi-star-fill"></i><i class="bi bi-star-fill"></i><i
                                                class="bi bi-star-fill"></i><i class="bi bi-star-fill"></i><i
                                                class="bi bi-star-fill"></i>
                                        </div>
                                        <p class="price-tag mb-2">৳ 1100.0</p>
                                        <a href="#" class="btn btn-primary btn-add-cart">Add to Cart</a>
                                    </div>
                                </div>
                                <div class="product-card card">
                                    <img src="https://placehold.co/300x300" class="card-img-top" alt="Product 6">
                                    <div class="product-details-body">
                                        <h5 class="product-title mb-1">Product Name 6</h5>
                                        <p class="product-meta mb-1">Category: Home Goods</p>
                                        <p class="product-meta mb-1">SKU: PN-006</p>
                                        <p class="product-meta text-success fw-bold mb-1"><i
                                                class="bi bi-check-circle-fill"></i> In stock</p>
                                        <div class="rating-stars mb-2">
                                            <i class="bi bi-star-fill"></i><i class="bi bi-star-fill"></i><i
                                                class="bi bi-star-fill"></i><i class="bi bi-star-fill"></i><i
                                                class="bi bi-star-fill"></i>
                                        </div>
                                        <p class="price-tag mb-2">৳ 1100.0</p>
                                        <a href="#" class="btn btn-primary btn-add-cart">Add to Cart</a>
                                    </div>
                                </div>
                                <div class="product-card card">
                                    <img src="https://placehold.co/300x300" class="card-img-top" alt="Product 6">
                                    <div class="product-details-body">
                                        <h5 class="product-title mb-1">Product Name 6</h5>
                                        <p class="product-meta mb-1">Category: Home Goods</p>
                                        <p class="product-meta mb-1">SKU: PN-006</p>
                                        <p class="product-meta text-success fw-bold mb-1"><i
                                                class="bi bi-check-circle-fill"></i> In stock</p>
                                        <div class="rating-stars mb-2">
                                            <i class="bi bi-star-fill"></i><i class="bi bi-star-fill"></i><i
                                                class="bi bi-star-fill"></i><i class="bi bi-star-fill"></i><i
                                                class="bi bi-star-fill"></i>
                                        </div>
                                        <p class="price-tag mb-2">৳ 1100.0</p>
                                        <a href="#" class="btn btn-primary btn-add-cart">Add to Cart</a>
                                    </div>
                                </div>
                                <div class="product-card card">
                                    <img src="https://placehold.co/300x300" class="card-img-top" alt="Product 6">
                                    <div class="product-details-body">
                                        <h5 class="product-title mb-1">Product Name 6</h5>
                                        <p class="product-meta mb-1">Category: Home Goods</p>
                                        <p class="product-meta mb-1">SKU: PN-006</p>
                                        <p class="product-meta text-success fw-bold mb-1"><i
                                                class="bi bi-check-circle-fill"></i> In stock</p>
                                        <div class="rating-stars mb-2">
                                            <i class="bi bi-star-fill"></i><i class="bi bi-star-fill"></i><i
                                                class="bi bi-star-fill"></i><i class="bi bi-star-fill"></i><i
                                                class="bi bi-star-fill"></i>
                                        </div>
                                        <p class="price-tag mb-2">৳ 1100.0</p>
                                        <a href="#" class="btn btn-primary btn-add-cart">Add to Cart</a>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </section>

@endif
@endif

@if(isset($offerSectionSetting) && $offerSectionSetting->is_visible && $offerSectionSetting->bundleOffer)
        @php
                            
                            $newGlobalCat = \App\Models\BundleOfferProduct::where('bundle_offer_id', $offerSectionSetting->bundleOffer->id)
                            ->get();
                            //dd($newGlobalCat);
                        @endphp

<section class="section mega-offer-wrapper"  style="background-image: {{ $offerSectionSetting->background_color ?? '#f8f9fa' }} !important;">
            <div class="mega-offer-section">
                <div class="container">
                    <div class="row">
                        <div class="col-12">
                            <div class="row g-0 ">
                                <div class="col-lg-6">
                                    <div class="mega-offer-banner" style="background-image: url('{{ $front_ins_url .'public/' .$offerSectionSetting->bundleOffer->image  }}');"></div>
                                </div>
                                <div class="col-lg-6 d-flex align-items-center justify-content-center">
                                    <div class="mega-offer-content">
                                        <h2>{{ $offerSectionSetting->bundleOffer->name ?? 'MEGA BUNDLE OFFER' }}</h2>
                                <p>{{ $offerSectionSetting->bundleOffer->title ?? 'Get upto 50% discount' }}</p>
                                        <div class="countdown-timer-offer" data-end-date="{{ $dealEndDateISO }}">
                                            <div class="timer-box">
                                                <div class="value" id="days-3">{{ $remaining['days'] }}</div>
                                                <div class="label">Days</div>
                                            </div>
                                            <div class="timer-box">
                                                <div class="value" id="hours-3">{{ $remaining['hours'] }}</div>
                                                <div class="label">Hours</div>
                                            </div>
                                            <div class="timer-box">
                                                <div class="value" id="minutes-3">{{ $remaining['minutes'] }}</div>
                                                <div class="label">Minutes</div>
                                            </div>
                                            <div class="timer-box">
                                                <div class="value" id="seconds-3">{{ $remaining['seconds'] }}</div>
                                                <div class="label">Seconds</div>
                                            </div>
                                        </div>
                                        <a href="{{ url($offerSectionSetting->route ?? '#') }}" class="btn btn-go-shopping">Go Shopping</a>
                                    </div>
                                </div>
                            </div>
                        </div>
                       
                        <div class="col-12 product-offer-slider-wrapper">
                            <div class="product-offer-slider">

                                  @forelse ($newGlobalCat as $deal)
            
            @php
                // Get the first product in the deal to use its image
                $firstProductId = $deal->product_id[0] ?? null;
                $firstProduct = \App\Models\Product::find($firstProductId) ?? null;

                // --- START: UPDATED PRICE CALCULATION LOGIC ---
                $originalTotalPrice = 0;
                
                // Determine how many products to count based on 'buy_quantity'.
                // Default to all products in the array if 'buy_quantity' is not set or invalid.
                $quantityToConsider = (isset($deal->buy_quantity) && $deal->buy_quantity > 0) 
                                      ? (int)$deal->buy_quantity 
                                      : count($deal->product_id);
                
                // Get the specific number of product IDs from the start of the array.
                $productIdsToSum = array_slice($deal->product_id, 0, $quantityToConsider);
                
                // Calculate the total base price for only those products.
                foreach ($productIdsToSum as $productId) {
                    if ($product = \App\Models\Product::find($productId)) {
                        $originalTotalPrice += $product->base_price;
                    }
                }
                // --- END: UPDATED PRICE CALCULATION LOGIC ---
            @endphp
@if(isset($firstProduct))
<a href="{{ route('offerProduct.show', $deal->id) }}">
            <div class="product-card-offer card">
                <img src="{{ $front_ins_url . 'public/uploads/' .$firstProduct->main_image[0] }}" class="card-img-left" alt="{{ $deal->title }}">
                <div class="product-details-offer">
                    <h5 class="product-title-offer">{{ Str::limit($deal->title, 10) }}</h5>
                    <p class="item-price-offer mb-0">
                        {{-- If there's a valid discount price, show both original and discounted price --}}
                        @if ($deal->discount_price > 0 && $deal->discount_price < $originalTotalPrice)
                            <span class="original-price">৳ {{ number_format($originalTotalPrice, 2) }}</span><br>
                            ৳ {{ number_format($deal->discount_price, 2) }}
                        @else
                            {{-- Otherwise, just show the calculated original price --}}
                            ৳ {{ number_format($originalTotalPrice, 2) }}
                        @endif
                    </p>
                </div>
            </div>
</a>
        @endif
        @empty
            <div class="col-12">
                <p class="text-center">No special offers available at the moment.</p>
            </div>
        @endforelse
                                {{-- <div class="product-card-offer card">
                                    <img src="{{asset('/')}}public/front/assets/img/product/product.webp" class="card-img-left" alt="Product 1">
                                    <div class="product-details-offer">
                                        <h5 class="product-title-offer">2 Drop</h5>
                                        <p class="item-price-offer mb-0">৳ 800.0</p>
                                    </div>
                                </div> --}}
                               
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </section>
@endif
 @if(isset($featuredCategories) && $featuredCategories->count() > 0)
        <section class="featured-category-section">
    <div class="container">
        <div class="category-header">
            <h2>FEATURED CATEGORY</h2>
            <p>Hurry and get coupon with every product</p>
        </div>

       
        <div class="row category-layout g-3">
            <!-- Left side: Large Banner -->
            <div class="col-lg-6">
                <div class="main-category-banner" style="background-image: url('{{  $front_ins_url .'public/' . $featuredCategories->first()->image}}');">
                    <div class="main-category-banner-content">
                        <h4 class="mb-3">{{ Str::upper($featuredCategories->first()->name) }}</h4>
                        <a href="{{route('animation.category.show', $featuredCategories->first()->slug)}}" class="btn btn-outline-light">Visit Now</a>
                    </div>
                </div>
            </div>

            <!-- Right side: Four Banners -->
            <div class="col-lg-6">
                <div class="row g-3">
                    {{-- Loop through the next four categories --}}
                    @foreach($featuredCategories->skip(1) as $category)
                    <div class="col-6">
                        <div class="sub-category-banner" style="background-image: url('{{ $front_ins_url .'public/' . $category->image }}');">
                            <div class="sub-category-banner-content">
                                <h5>{{ Str::upper($category->name) }}</h5>
                                {{-- You can add a subtitle field to your animation_categories table for this --}}
                                <p class="mb-2">New Collection</p>
                                <a href="{{ route('animation.category.show', $category->slug) }}" class="btn btn-outline-light btn-sm">Visit Now</a>
                            </div>
                        </div>
                    </div>
                    @endforeach
                </div>
            </div>
        </div>
       
    </div>
</section>
 @endif
        @if(isset($footerBanner))
        
        <section class="why-section">
    <div class="container">
        <div class="why-header">
            <h2>WHY Khan Sneaker STORE?</h2>
        </div>
                    <div class="row why-layout">
                <!-- Left side: Banner -->
                <div class="col-lg-5">
                    <div class="left-banner">
                        <div class="left-banner-content">
                            <img src="{{ $front_ins_url . 'public/' . $footerBanner->image }}">
                        </div>
                    </div>
                </div>

                <!-- Right side: Benefits Grid -->
                <div class="col-lg-7">
                    <div class="d-flex align-items-center">
                    <div class="row right-benefits-grid ">
                        <!-- Benefit 1 -->
                        <div class="col-md-6 mb-4">
                            <div class="benefit-item">
                                <div class="icon-container"><i class="bi bi-person-bounding-box"></i></div>
                                <div class="benefit-item-content">
                                    <h5>UNIQUENESS AND STYLE</h5>
                                    <p>Stand out with exclusive designs that celebrate your individuality.</p>
                                </div>
                            </div>
                        </div>
                        <!-- Benefit 2 -->
                        <div class="col-md-6 mb-4">
                            <div class="benefit-item">
                                <div class="icon-container"><i class="bi bi-tags-fill"></i></div>
                                <div class="benefit-item-content">
                                    <h5>QUALITY AND AFFORDABILITY</h5>
                                    <p>High-quality fashion at prices that won't break the bank.</p>
                                </div>
                            </div>
                        </div>
                        <!-- Benefit 3 -->
                        <div class="col-md-6 mb-4">
                            <div class="benefit-item">
                                <div class="icon-container"><i class="bi bi-toggles2"></i></div>
                                <div class="benefit-item-content">
                                    <h5>VERSATILITY FOR EVERYONE</h5>
                                    <p>From casual to polished, find styles that fit every lifestyle.</p>
                                </div>
                            </div>
                        </div>
                        <!-- Benefit 4 -->
                        <div class="col-md-6 mb-4">
                            <div class="benefit-item">
                                <div class="icon-container"><i class="bi bi-emoji-smile"></i></div>
                                <div class="benefit-item-content">
                                    <h5>CONFIDENCE AND COMFORT</h5>
                                    <p>Feel confident and comfortable with every piece you wear.</p>
                                </div>
                            </div>
                        </div>
                        <!-- Benefit 5 -->
                        <div class="col-md-6 mb-4">
                            <div class="benefit-item">
                                <div class="icon-container"><i class="bi bi-hand-thumbs-up"></i></div>
                                <div class="benefit-item-content">
                                    <h5>CUSTOMER-CENTRIC APPROACH</h5>
                                    <p>Designed with you in mind, offering unmatched experiences.</p>
                                </div>
                            </div>
                        </div>
                        <!-- Benefit 6 -->
                        <div class="col-md-6 mb-4">
                            <div class="benefit-item">
                                <div class="icon-container"><i class="bi bi-lightbulb-fill"></i></div>
                                <div class="benefit-item-content">
                                    <h5>DISCOVER THE UNEXPECTED</h5>
                                    <p>Innovative pieces that refresh your style effortlessly.</p>
                                </div>
                            </div>
                        </div>
                    </div>
                    </div>
                </div>
            </div>
        <!--<div class="row why-layout">-->
        <!--    <div class="col-lg-12">-->
        <!--        -->
        <!--        <div class="left-banner" style="background-image: url('https://testadmin.spotlightattires.com/public/uploads/banners/footer-banner-43178bab-bf94-4175-83ee-a24538366b85.webp');">-->
        <!--            -->
        <!--        </div>-->
        <!--    </div>-->
        <!--</div>-->
    </div>
</section>


@endif

    </main>
    <!-- Quick View Modal -->
    <div class="modal fade" id="quickViewModal" tabindex="-1" aria-labelledby="quickViewModalLabel" aria-hidden="true">
    <div class="modal-dialog modal-dialog-centered modal-lg">
        <div class="modal-content">
            <div class="modal-header">
                <h5 class="modal-title" id="quickViewModalLabel">Product Details</h5>
                <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
            </div>
            <div class="modal-body" id="quickViewModalBody">
                <div class="text-center p-5">
                    <div class="spinner-border" style="width: 3rem; height: 3rem;" role="status">
                        <span class="visually-hidden">Loading...</span>
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>
<!-- Quick View Modal -->
@endsection
@section('script')
<script>
    $(document).ready(function() {
        // Use event delegation for buttons in sliders
        $('body').on('click', '.btn-add-cart', function(e) {
            e.preventDefault(); // Prevents the link from jumping to the top of the page

            const productId = $(this).data('product-id');
            const modal = $('#quickViewModal');
            const modalBody = $('#quickViewModalBody');

            // --- START: MODIFIED URL GENERATION ---
            // Create a URL template using the named route and a placeholder
            let urlTemplate = "{{ route('product.quick_view', ['id' => ':id']) }}";
            // Replace the placeholder with the actual product ID
            let productUrl = urlTemplate.replace(':id', productId);
            // --- END: MODIFIED URL GENERATION ---

            // Show the modal
            modal.modal('show');

            // Set a loading state
            modalBody.html('<div class="text-center p-5"><div class="spinner-border" style="width: 3rem; height: 3rem;" role="status"><span class="visually-hidden">Loading...</span></div></div>');

            // Fetch product details via AJAX
            $.ajax({
                url: productUrl, // Use the dynamically generated URL
                type: 'GET',
                success: function(response) {
                    modalBody.html(response);
                },
                error: function() {
                    modalBody.html('<p class="text-danger text-center">Sorry, we could not load the product details. Please try again.</p>');
                }
            });
        });
    });
</script>
<script>
    $(function() {
    // Select the timer container div
    const timerContainer = $('.countdown-timer-offer');
    
    // Get the end date string from the data attribute
    const endDateString = timerContainer.data('end-date');
    
    // If there's no date, do nothing
    if (!endDateString) {
        return; 
    }
    
    // Convert the date string into a format JavaScript can use
    const endDate = new Date(endDateString).getTime();

    // Set an interval to run a function every 1000 milliseconds (1 second)
    const timerInterval = setInterval(function() {
        // Get the current time
        const now = new Date().getTime();

        // Calculate the time remaining between now and the end date
        const distance = endDate - now;

        // If the countdown is finished, stop the timer and show a message
        if (distance < 0) {
            clearInterval(timerInterval);
            timerContainer.html("<div style='font-size: 1.5em; color: red;'>Offer has expired!</div>");
            return;
        }
        
        // Calculate the days, hours, minutes, and seconds from the remaining time
        const days = Math.floor(distance / (1000 * 60 * 60 * 24));
        const hours = Math.floor((distance % (1000 * 60 * 60 * 24)) / (1000 * 60 * 60));
        const minutes = Math.floor((distance % (1000 * 60 * 60)) / (1000 * 60));
        const seconds = Math.floor((distance % (1000 * 60)) / 1000);

        // A simple function to add a leading zero (e.g., 9 becomes "09")
        const pad = (num) => String(num).padStart(2, '0');

        // Use jQuery to find each element by its ID and update its text
        $('#days-3').text(pad(days));
        $('#hours-3').text(pad(hours));
        $('#minutes-3').text(pad(minutes));
        $('#seconds-3').text(pad(seconds));

    }, 1000);
});
</script>
@endsection