@forelse($bundleDeals as $deal)
    <div class="col">
        <div class="product-card card h-100">
            @php
                // --- 1. Get Image ---
                $displayProduct = null;
                if(is_array($deal->product_id)) {
                    foreach($deal->product_id as $pid) {
                        if(isset($productsCollection[$pid])) {
                            $displayProduct = $productsCollection[$pid];
                            break;
                        }
                    }
                }
                
                $image = ($displayProduct && is_array($displayProduct->main_image) && count($displayProduct->main_image) > 0)
                            ?   $front_ins_url . 'public/uploads/' . $displayProduct->main_image[0]
                            : 'https://placehold.co/400x400';

                // --- 2. Calculate Total Base Price ---
                $totalBasePrice = 0;
                if (is_array($deal->product_id)) {
                    $quantityToConsider = (isset($deal->buy_quantity) && $deal->buy_quantity > 0)
                                          ? (int)$deal->buy_quantity
                                          : count($deal->product_id);

                    $productIdsToSum = array_slice($deal->product_id, 0, $quantityToConsider);

                    foreach ($productIdsToSum as $pid) {
                        if (isset($productsCollection[$pid])) {
                            $totalBasePrice += $productsCollection[$pid]->base_price;
                        }
                    }
                }
                
                // --- 3. NEW: Calculate Average Rating for this specific Deal ---
                $totalReviewsCount = 0;
                $ratingSum = 0;
                if(is_array($deal->product_id)) {
                    foreach($deal->product_id as $pid) {
                        if(isset($productsCollection[$pid])) {
                            $product = $productsCollection[$pid];
                            $totalReviewsCount += $product->reviews_count;
                            $ratingSum += ($product->reviews_avg_rating * $product->reviews_count);
                        }
                    }
                }
                $dealAverageRating = ($totalReviewsCount > 0) ? $ratingSum / $totalReviewsCount : 0;

            @endphp
            
            <a href="{{ route('offerProduct.show', $deal->id) }}">
                <img src="{{ $image }}" alt="{{ $deal->title }}" class="card-img-top img-fluid">
            </a>

            <div class="product-details-body">
                <h5 class="product-title mb-1">{{ $deal->title }}</h5>

                {{-- START: DYNAMIC STAR RATING --}}
                <div class="rating-stars mb-2">
                    @for ($i = 1; $i <= 5; $i++)
                        <i class="bi {{ $i <= round($dealAverageRating) ? 'bi-star-fill text-warning' : 'bi-star text-muted' }}"></i>
                    @endfor
                </div>
                {{-- END: DYNAMIC STAR RATING --}}

                <p class="price-tag mb-2">
                    @if($deal->discount_price > 0 && $deal->discount_price < $totalBasePrice)
                        <del class="text-muted" style="font-weight: 100 !important;">৳ {{ number_format($totalBasePrice) }}</del>
                        <span class="fw-bold">৳ {{ number_format($deal->discount_price) }}</span>
                    @else
                        <span class="fw-bold">৳ {{ number_format($totalBasePrice) }}</span>
                    @endif
                </p>
                <a href="{{ route('offerProduct.show', $deal->id) }}" class="btn btn-primary btn-add-cart w-100">View Deal</a>
            </div>
        </div>
    </div>
@empty
    <div class="col-12 text-center py-5">
        <h4>No Deals Found</h4>
        <p>There are no special deals for this offer at the moment.</p>
    </div>
@endforelse