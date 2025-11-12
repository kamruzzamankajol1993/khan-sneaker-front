{{-- This partial view contains the loop for rendering product cards --}}
@if(count($products) > 0)
@forelse ($products as $product)
    <div class="col">
        <div class="product-card card h-100">
          @php
        // --- DEFAULT IMAGES (Image 1) ---
        $mobileImage = (is_array($product->thumbnail_image) && count($product->thumbnail_image) > 0)
                        ? $front_ins_url . 'public/uploads/' . $product->thumbnail_image[0]
                        : 'https://placehold.co/400x400';
        $desktopImage = (is_array($product->main_image) && count($product->main_image) > 0)
                        ? $front_ins_url . 'public/uploads/' . $product->main_image[0]
                        : 'https://placehold.co/400x400';

        // --- HOVER IMAGES (Image 2) ---
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

        // --- NEW: Find the Extra Category Name ---
        $extraCategoryName = null;
        $extraCategoryAssignment = $product->assigns->where('type', 'other')->first();
        if ($extraCategoryAssignment) {
            $extraCategory = \App\Models\ExtraCategory::find($extraCategoryAssignment->category_id);
            if ($extraCategory) {
                $extraCategoryName = $extraCategory->name;
            }
        }
    @endphp

    <a href="{{ route('product.show', $product->slug) }}" class="product-image-container">
    
    @if ($extraCategoryName)
        <span class="product-badge">{{ $extraCategoryName }}</span>
    @endif

    <picture>
        <source media="(min-width: 992px)" srcset="{{ $desktopImage }}">
        <img src="{{ $mobileImage }}" alt="{{ $product->name }}" class="card-img-top img-fluid">
    </picture>

    <picture class="product-image-hover">
        <source media="(min-width: 992px)" srcset="{{ $desktopImageHover }}">
        <img src="{{ $mobileImageHover }}" alt="{{ $product->name }} hover" class="card-img-top img-fluid">
    </picture>

    
    </a>
            <div class="product-details-body">
                <h5 class="product-title mb-1"><a href="{{ route('product.show', $product->slug) }}">{{$product->name}}</a></h5>
                {{-- ▼▼▼ THIS LINE IS NOW UPDATED ▼▼▼ --}}
                <p class="product-meta mb-1">Category: {{ $product->productCategoryAssignment->category->name ?? 'N/A' }}</p>
                {{-- ▲▲▲ THIS LINE IS NOW UPDATED ▲▲▲ --}}

                @if($totalStock > 0)
                    <p class="product-meta text-success fw-bold mb-1"><i class="bi bi-check-circle-fill"></i> In stock</p>
                @else
                    <p class="product-meta text-danger fw-bold mb-1"><i class="bi bi-x-circle-fill"></i> Out of stock</p>
                @endif

                 <div class="rating-stars mb-2">
                    @php
                        $rating = round($product->reviews_avg_rating ?? 0);
                    @endphp
                    @for ($i = 1; $i <= 5; $i++)
                        @if ($i <= $rating)
                            <i class="bi bi-star-fill"></i>
                        @else
                            <i class="bi bi-star"></i>
                        @endif
                    @endfor
                </div>
                <p class="price-tag mb-2">
                    @if($product->discount_price)
                        <del class="text-muted" style="font-weight: 100 !important;">৳ {{ number_format($product->base_price) }}</del>
                        <span class="fw-bold">৳ {{ number_format($product->discount_price) }}</span>
                    @else
                        <span class="fw-bold">৳ {{ number_format($product->base_price) }}</span>
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

                {{-- <a href="#" class="btn btn-primary btn-add-cart" data-product-id="{{ $product->id }}">Add to Cart</a> --}}
            </div>
        </div>
    </div>
@empty
    <div class="col-12 text-center py-5">
        <h4>No Products Found</h4>
        <p>Try adjusting your filters to find what you're looking for.</p>
    </div>
@endforelse

@else
  <div class="col-12 text-center py-5">
    
    {{-- GIF Animation --}}
     
    
    {{-- Not Found Message --}}
    <h4 class="mt-4">No Products Found</h4>
    <p class="text-muted">Sorry, we couldn't find any products matching your selection.</p>
    
</div>
@endif