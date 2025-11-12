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
      <h5 class="fw-bold mb-3 filter_title">Product Categories</h5>
    <ul class="list-unstyled mb-4 filter_listing">
        @foreach($categoryList as $cat)
            <li class="mb-2">
                {{-- Use the 'children' relationship to check for subcategories --}}
                <div class="d-flex justify-content-between align-items-center"
                     @if($cat->children->isNotEmpty()) data-bs-toggle="collapse" data-bs-target="#collapse-{{ $cat->slug }}" role="button" @endif>
                    <a href="#" class="text-dark text-decoration-none main-category-filter" data-id="{{ $cat->id }}">{{ $cat->name }}</a>
                    @if($cat->children->isNotEmpty()) <i class="bi bi-chevron-down"></i> @endif
                </div>

                {{-- If children exist, create the collapsible list --}}
                @if($cat->children->isNotEmpty())
                    <div class="collapse" id="collapse-{{ $cat->slug }}">
                        <ul class="list-unstyled ms-3 mt-2">
                            {{-- Loop through the 'children' relationship --}}
                            @foreach($cat->children as $child)
                                <li><a class="d-block py-1 text-dark text-decoration-none subcategory-filter" href="#" data-id="{{ $child->id }}">{{ $child->name }}</a></li>
                            @endforeach
                        </ul>
                    </div>
                @endif
            </li>
        @endforeach
    </ul>

    <hr>
    <hr>
    <h5 class="fw-bold my-3 filter_title">Animation Categories</h5>
    <ul class="list-unstyled mb-4 filter_listing">
        @foreach($animationCategoryList as $item)
            <li class="mb-2">
                <a href="#" class="text-dark text-decoration-none animation-category-filter" data-id="{{ $item->id }}">{{ $item->name }}</a>
            </li>
        @endforeach
    </ul>
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
   
</div>