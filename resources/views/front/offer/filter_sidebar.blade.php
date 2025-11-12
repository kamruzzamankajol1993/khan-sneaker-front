<div class="filter-section">
    <h5 class="fw-bold mb-3 filter_title">Available Offers</h5>
    <ul class="list-unstyled mb-4 filter_listing">
        @forelse($offerList as $item)
            <li class="mb-2">
                <a href="#" class="text-dark text-decoration-none offer-filter" data-id="{{ $item->id }}">
                    {{ $item->name }}
                </a>
            </li>
        @empty
            <li class="text-muted">No other offers available.</li>
        @endforelse
    </ul>

    {{-- ADD THIS ENTIRE BLOCK FOR THE PRICE FILTER --}}
    <hr>
    <h5 class="fw-bold my-3 filter_title">Filter by Price</h5>
    <div class="range-slider-container mb-3">
        {{-- You can adjust the max value as needed --}}
        <input type="range" class="form-range" id="min-price-slider" min="0" max="20000" value="0">
        <input type="range" class="form-range" id="max-price-slider" min="0" max="20000" value="20000">
    </div>
    <div class="d-flex justify-content-between align-items-center mb-3">
        <span class="text-muted" id="price-range-display">Price: ৳ 0 - ৳ 20000</span>
        <button class="btn btn-sm btn-primary" id="price-filter-btn">Filter</button>
    </div>
    {{-- END OF NEW BLOCK --}}
</div>