<div class="filter-section">
     <h5 class="fw-bold my-3 filter_title">Status</h5>
    <div class="form-check mb-2">
        <input class="form-check-input stock-status-filter" type="radio" name="stock-status" id="all-stock" value="" checked>
        <label class="form-check-label" for="all-stock">All</label>
    </div>
    <div class="form-check mb-2">
        <input class="form-check-input stock-status-filter" type="radio" name="stock-status" id="on-sale" value="offer">
        <label class="form-check-label" for="on-sale">Offer</label>
    </div>
    <div class="form-check">
        <input class="form-check-input stock-status-filter" type="radio" name="stock-status" id="in-stock" value="in_stock">
        <label class="form-check-label" for="in-stock">In Stock</label>
    </div>
    {{-- END OF NEW BLOCK --}}
    <h5 class="fw-bold mb-3 filter_title">Animation Categories</h5>
    <ul class="list-unstyled mb-4 filter_listing">
        @forelse($animationCategoryList as $item)
            <li class="mb-2">
                <a href="#" class="text-dark text-decoration-none animation-category-filter" data-id="{{ $item->id }}">
                    {{ $item->name }}
                </a>
            </li>
        @empty
            <li class="text-muted">No categories available.</li>
        @endforelse
    </ul>

    {{-- ADD THIS ENTIRE BLOCK FOR PRICE & STOCK FILTERS --}}
    <hr>
    <h5 class="fw-bold my-3 filter_title">Filter by Price</h5>
    <div class="range-slider-container mb-3">
        <input type="range" class="form-range" id="min-price-slider" min="0" max="10000" value="0">
        <input type="range" class="form-range" id="max-price-slider" min="0" max="10000" value="10000">
    </div>
    <div class="d-flex justify-content-between align-items-center mb-3">
        <span class="text-muted" id="price-range-display">Price: ৳ 0 - ৳ 10000</span>
        <button class="btn btn-sm btn-primary" id="price-filter-btn">Filter</button>
    </div>

    <hr>
     {{-- --- NEW: FILTER BY SIZE SECTION --- --}}
    @if(isset($sizes) && $sizes->isNotEmpty())
    <h5 class="fw-bold my-3 filter_title">Filter by Size</h5>
    <div class="size-filter-container">
        @foreach($sizes as $size)
        <div class="form-check mb-2">
            <input class="form-check-input size-filter" type="checkbox" value="{{ $size->name }}" id="size-{{ $size->id }}">
            <label class="form-check-label" for="size-{{ $size->id }}">
                {{ $size->name }}
            </label>
        </div>
        @endforeach
    </div>
    <hr>
    @endif
    {{-- --- END: FILTER BY SIZE SECTION --- --}}
   
</div>