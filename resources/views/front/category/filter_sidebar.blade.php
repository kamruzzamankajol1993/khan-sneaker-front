{{-- This partial contains the filter options for both desktop and mobile --}}
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
            <div class="d-flex justify-content-between align-items-center"
                 {{-- Check for children to make the row expandable --}}
                 @if($cat->children->isNotEmpty())
                     data-bs-toggle="collapse"
                     data-bs-target="#collapse-{{ $cat->slug }}"
                     {{-- Expand the parent category if it matches the current page's category --}}
                     aria-expanded="{{ isset($category) && $category->id === $cat->id ? 'true' : 'false' }}"
                     role="button"
                 @endif
            >
                {{-- Add 'active' class to the parent category link if it's the one being viewed --}}
                <a href="#" class="text-dark text-decoration-none main-category-filter {{ (isset($category) && $category->id === $cat->id && !isset($subcategory)) ? 'active' : '' }}" data-id="{{ $cat->id }}">{{ $cat->name }}</a>

                @if($cat->children->isNotEmpty())
                    <i class="bi bi-chevron-down"></i>
                @endif
            </div>

            {{-- Loop through child categories if they exist --}}
            @if($cat->children->isNotEmpty())
                {{-- Add 'show' class to display the child list if the parent is active --}}
                <div class="collapse {{ isset($category) && $category->id === $cat->id ? 'show' : '' }}" id="collapse-{{ $cat->slug }}">
                    <ul class="list-unstyled ms-3 mt-2">
                        @foreach($cat->children as $child)
                            <li>
                                {{-- Add 'active' class to the subcategory link if it's the one being viewed --}}
                                <a class="d-block py-1 text-dark text-decoration-none subcategory-filter {{ (isset($subcategory) && $subcategory->id === $child->id) ? 'active' : '' }}" href="#" data-id="{{ $child->id }}">{{ $child->name }}</a>
                            </li>
                        @endforeach
                    </ul>
                </div>
            @endif
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