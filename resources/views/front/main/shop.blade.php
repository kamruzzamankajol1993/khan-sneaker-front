@extends('front.master.master')

@section('title', 'Shop All Products')

@section('css')
<style>
    #loading-spinner { display: none; text-align: center; padding: 20px 0; }
    .main-category-filter.active,
    .subcategory-filter.active,
    .animation-category-filter.active { 
        font-weight: bold; 
        color: #0d6efd !important; 
    }

       /* --- NEW CSS FOR STICKY SIDEBAR --- */
    .sticky-filter {
        position: -webkit-sticky; /* For Safari */
        position: sticky;
        top: 100px; /* Adjust this value based on your header's height */
        align-self: flex-start; /* Prevents the column from stretching */
        height: calc(100vh - 100px); /* Sets a max-height for the sidebar */
        overflow-y: auto; /* Adds a scrollbar if the filters are too long */
    }
    /* --- END OF NEW CSS --- */
     
    
   /* --- FINAL PRODUCT CARD STYLES --- */
    .product-card {
        transition: box-shadow 0.3s ease;
        position: relative;
        overflow: hidden;
    }
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

    /* DESKTOP: Position buttons over the image on hover */
    .product-actions {
        position: absolute;
        top: 35%; /* Adjusted for better vertical centering on the image */
        left: 50%;
        z-index: 10;
        display: flex;
        gap: 10px;
        opacity: 0;
        transform: translate(-50%, -50%) scale(0.9);
        transition: opacity 0.3s ease, transform 0.3s ease, visibility 0.3s;
        visibility: hidden; /* Prevent interaction when hidden */
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
        box-shadow: 0 2px 5px rgba(0,0,0,0.15);
        transition: background-color 0.2s, color 0.2s, transform 0.2s ease;
        text-decoration: none;
    }
    .product-action-btn:hover {
        background-color: #0d6efd;
        color: #ffffff;
        transform: translateY(-2px);
    }
    
    /* Trigger hover effects */
    .product-card:hover .product-actions {
        opacity: 1;
        transform: translate(-50%, -50%) scale(1);
        visibility: visible;
    }
    .product-card:hover .product-image-hover {
        opacity: 1;
    }
    .product-card:hover .product-image-container picture img {
        transform: scale(1.05);
    }

#active-filters-container {
    display: none; /* Hidden by default */
    padding-bottom: 1rem;
    margin-bottom: 1rem;
    border-bottom: 1px solid #eee;
}
.filter-tag {
    display: inline-flex;
    align-items: center;
    background-color: #e9ecef;
    border: 1px solid #dee2e6;
    border-radius: 1rem;
    padding: 0.25rem 0.75rem;
    margin-right: 0.5rem;
    margin-bottom: 0.5rem;
    font-size: 0.875rem;
}
.remove-filter {
    margin-left: 0.5rem;
    cursor: pointer;
    font-weight: bold;
}
#clear-all-filters {
    font-size: 0.875rem;
    font-weight: bold;
    color: #dc3545;
    text-decoration: none;
}
#clear-all-filters:hover {
    text-decoration: underline;
}
/* --- MOBILE RESPONSIVE STYLES --- */
    @media (max-width: 767.98px) {
        /* This overrides absolute positioning and places buttons in the normal content flow */
        .product-actions {
            position: static;
            visibility: visible;
            opacity: 1;
            transform: none;
            justify-content: center;
            margin-top: 8px;
            gap: 2px;
            margin-bottom: 12px;
            background-color: transparent;
            padding: 0;
            backdrop-filter: none;
        }

        /* "Perfect Circle" styles for mobile buttons */
        .product-action-btn {
            width: 35px;
            height: 35px;
            min-width: 35px;
            border-radius: 50%;
            border: none;
            background-color: #ffffff;
            box-shadow: 0 4px 8px rgba(0, 0, 0, 0.08), 0 1px 3px rgba(0, 0, 0, 0.06);
            transition: all 0.2s ease-out;
        }
        .product-action-btn i {
            font-size: 1.1rem;
            line-height: 1;
        }
        .product-action-btn:active {
            transform: scale(0.94);
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
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
</style>

@endsection

@section('body')
<main>
    <section class="section">
        <div class="container py-4">
          
            <div class="row">
                <div class="col-12 d-block d-md-none mb-3">
                    <button class="btn btn-dark w-100" type="button" data-bs-toggle="offcanvas" data-bs-target="#mobile-filter-menu">
                        <i class="bi bi-funnel-fill"></i> Filters
                    </button>
                </div>

                <div class="col-md-3 d-none d-md-block sticky-filter">
                    @include('front.main.filter_sidebar')
                </div>

                <div class="col-md-9">
                     <!--- new filter section --->
                    <div class="d-flex justify-content-end">
                    <div class="row mb-3">
                        <div class="col">
                            
                                
                            <select class="form-select" id="sort-select-new" aria-label="Sort Products">
                                <option value="default">Sort by</option>
                                <option value="name_asc">A to Z</option>
                                <option value="price_asc">Price: Low to High</option>
                                <option value="price_desc">Price: High to Low</option>
                                <option value="newest">Newest Arrivals</option>
                                <option value="popularity">Most Popular</option>
                            </select>
                            </div>
                        </div>
                    </div>
                    <!--- end new filter section ---->
                    <div id="active-filters-container">
        <div id="active-filters-list" class="d-inline">
            </div>
        <a href="#" id="clear-all-filters" class="ms-2">Clear All</a>
    </div>
                    <div class="product-grid">
                        <div id="product-list" class="row row-cols-2 row-cols-sm-2 row-cols-lg-3 row-cols-xl-4 g-3">
                            @include('front.category.product_card_partial', ['products' => $products])
                        </div>
                    </div>
                    <div id="loading-spinner">
                        <div class="spinner-border text-primary" role="status">
                            <span class="visually-hidden">Loading...</span>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <div class="offcanvas offcanvas-start" tabindex="-1" id="mobile-filter-menu">
            <div class="offcanvas-header"><h5 class="offcanvas-title">Filters</h5><button type="button" class="btn-close" data-bs-dismiss="offcanvas" aria-label="Close"></button></div>
            <div class="offcanvas-body">@include('front.main.filter_sidebar')</div>
        </div>
    </section>
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
    // Handles all the filtering, AJAX loading, and URL updating logic
    $(document).ready(function() {
        let page = 2;
        let hasMorePages = {{ $products->hasMorePages() ? 'true' : 'false' }};
        let isLoading = false;
        let currentRequest = null;

        /**
         * Reads the current URL's query string and sets the filter inputs
         * to match. This runs once on page load.
         */
        function setFiltersFromUrl() {
            const params = new URLSearchParams(window.location.search);

            // Set Price sliders
            if (params.has('min_price')) $('#min-price-slider').val(params.get('min_price'));
            if (params.has('max_price')) $('#max-price-slider').val(params.get('max_price'));
            
            // Update Price range display text
            let min = $('#min-price-slider').val();
            let max = $('#max-price-slider').val();
            $('#price-range-display').text(`Price: ৳ ${min} - ৳ ${max}`);

            // Set Stock Status radio button
            if (params.has('stock_status')) {
                $(`input[name="stock-status"][value="${params.get('stock_status')}"]`).prop('checked', true);
            }

            // Set Size checkboxes
            if (params.has('sizes[]')) {
                const sizes = params.getAll('sizes[]');
                $('.size-filter').prop('checked', false); // First, uncheck all
                sizes.forEach(size => {
                    $(`.size-filter[value="${size}"]`).prop('checked', true);
                });
            }
            
            // Set active category links
            $('.main-category-filter, .subcategory-filter, .animation-category-filter').removeClass('active');
            if (params.has('category_id')) $('.main-category-filter[data-id="' + params.get('category_id') + '"]').addClass('active');
            if (params.has('subcategory_id')) $('.subcategory-filter[data-id="' + params.get('subcategory_id') + '"]').addClass('active');
            if (params.has('animation_category_id')) $('.animation-category-filter[data-id="' + params.get('animation_category_id') + '"]').addClass('active');

            // Set Sorting dropdown
            if (params.has('sort_by')) {
                $('#sort-select-new').val(params.get('sort_by'));
            }

            updateActiveFiltersDisplay();
        }

        /**
         * Reads the current filter state and updates the browser's URL
         * without reloading the page.
         */
        function updateUrl() {
            const filters = getFilters();
            // Remove empty or null values so the URL is clean
            const cleanFilters = Object.fromEntries(
                Object.entries(filters).filter(([_, v]) => v != null && v !== '' && v.length !== 0)
            );
            
            const queryString = $.param(cleanFilters);
            const newUrl = window.location.pathname + (queryString ? '?' + queryString : '');
            
            // Use pushState to change the URL
            history.pushState({path: newUrl}, '', newUrl);
        }
        
        /**
         * Reads all filter inputs and returns a clean object
         * for the AJAX request and URL update.
         */
        function getFilters() {
            const selectedSizes = $('.size-filter:checked').map(function() { return $(this).val(); }).get();
            return {
                category_id: $('.main-category-filter.active').data('id'),
                subcategory_id: $('.subcategory-filter.active').data('id'),
                animation_category_id: $('.animation-category-filter.active').data('id'),
                min_price: $('#min-price-slider').val(),
                max_price: $('#max-price-slider').val(),
                stock_status: $('input[name="stock-status"]:checked').val(),
                sort_by: $('#sort-select-new').val(),
                'sizes[]': selectedSizes // Use 'sizes[]' to send as an array
            };
        }

        /**
         * Loads products via AJAX. If it's a new filter action, it updates the URL first.
         * @param {boolean} reset - If true, clears the product list and resets to page 1.
         */
        function loadProducts(reset = false) {
            if (isLoading) return;

            if (reset) {
                page = 1;
                $('#product-list').html('');
                updateUrl(); // This is the key change for shareable links
            }
            
            updateActiveFiltersDisplay();
            isLoading = true;
            $('#loading-spinner').show();
            if (currentRequest) currentRequest.abort();

            // Determine the correct AJAX endpoint based on the current page
            let ajaxUrl = '{{ route("shop.ajax_filter") }}'; // Default to shop filter
            @if(Request::routeIs('category.show') || Request::routeIs('subcategory.show'))
                ajaxUrl = '{{ route("products.filter") }}';
            @elseif(Request::routeIs('animation.category.show'))
                ajaxUrl = '{{ route("animation.category.filter") }}';
            @elseif(Request::routeIs('products.search'))
                ajaxUrl = '{{ route("products.ajax_search_filter") }}';
            @elseif(Request::routeIs('extra_category_offer.show'))
                ajaxUrl = '{{ route("discount.ajax_filter") }}';
            @endif

            currentRequest = $.ajax({
                url: `${ajaxUrl}?page=${page}`,
                type: 'GET',
                data: getFilters(),
                success: function(response) {
                    if (reset) $('#product-list').html(response.html);
                    else $('#product-list').append(response.html);
                    hasMorePages = response.hasMorePages;
                    page++;
                    if (!hasMorePages) $('#loading-spinner').hide();
                },
                error: function(xhr, status, error) { if (status !== 'abort') console.error("Error:", error); },
                complete: function() { isLoading = false; if (hasMorePages) $('#loading-spinner').hide(); }
            });
        }
        
        /**
         * Manages the "active filter" tags displayed above the product grid.
         * This function does not need changes.
         */
        function updateActiveFiltersDisplay() {
    const filtersList = $('#active-filters-list');
    const filtersContainer = $('#active-filters-container');
    filtersList.html(''); // Clear existing tags
    let hasActiveFilters = false;
    
    // NEW: A Set to keep track of IDs we've already created a tag for.
    const processedIds = new Set();

    $('.main-category-filter.active, .subcategory-filter.active, .animation-category-filter.active').each(function() {
        const id = $(this).data('id');

        // NEW: If we've already processed this ID, skip to the next item.
        if (processedIds.has(id)) {
            return; // This is like 'continue' in a for loop
        }
        // NEW: Add the current ID to our set so we don't process it again.
        processedIds.add(id);

        const text = $(this).text();
        const type = $(this).hasClass('main-category-filter') ? 'category' :
                     $(this).hasClass('subcategory-filter') ? 'subcategory' : 'animation';
        
        filtersList.append(
            `<span class="filter-tag" data-filter-type="${type}" data-filter-value="${id}">${text} <span class="remove-filter" title="Remove filter">&times;</span></span>`
        );
        hasActiveFilters = true;
    });

    // The rest of the function for price, stock, size, and sorting remains the same
    const minPrice = $('#min-price-slider').val();
    const maxPrice = $('#max-price-slider').val();
    if (minPrice > 0 || maxPrice < 10000) {
        filtersList.append(`<span class="filter-tag" data-filter-type="price">Price: ৳ ${minPrice} - ৳ ${maxPrice} <span class="remove-filter" title="Remove filter">&times;</span></span>`);
        hasActiveFilters = true;
    }
    const stockStatus = $('input[name="stock-status"]:checked');
    if (stockStatus.val() !== "") {
        filtersList.append(`<span class="filter-tag" data-filter-type="stock">${stockStatus.next('label').text()} <span class="remove-filter" title="Remove filter">&times;</span></span>`);
        hasActiveFilters = true;
    }
    $('.size-filter:checked').each(function() {
        const size = $(this).val();
        filtersList.append(`<span class="filter-tag" data-filter-type="size" data-filter-value="${size}">${size} <span class="remove-filter" title="Remove filter">&times;</span></span>`);
        hasActiveFilters = true;
    });
    const sortSelect = $('#sort-select-new');
    if (sortSelect.val() && sortSelect.val() !== 'default') {
        filtersList.append(`<span class="filter-tag" data-filter-type="sort">Sort by: ${sortSelect.find('option:selected').text()} <span class="remove-filter" title="Remove filter">&times;</span></span>`);
        hasActiveFilters = true;
    }

    if (hasActiveFilters) {
        filtersContainer.slideDown(200);
    } else {
        filtersContainer.slideUp(200);
    }
}

        /* -------------------------------------------------------------------------- */
        /* EVENT LISTENERS                              */
        /* -------------------------------------------------------------------------- */

        // Set the initial state of the UI from the URL on page load
        setFiltersFromUrl();

        // Listen for changes on all filter inputs
        $('#sort-select-new, .stock-status-filter, .size-filter').on('change', () => loadProducts(true));
        $('#price-filter-btn').on('click', () => loadProducts(true));

        function handleCategoryClick(selector) {
            $(document).on('click', selector, function(e) {
                e.preventDefault();
                const $el = $(this);
                const wasActive = $el.hasClass('active');
                $('.main-category-filter, .subcategory-filter, .animation-category-filter').removeClass('active');
                if (!wasActive) {
                    $el.addClass('active');
                }
                loadProducts(true);
            });
        }
        handleCategoryClick('.main-category-filter');
        handleCategoryClick('.subcategory-filter');
        handleCategoryClick('.animation-category-filter');

        // Update price range text as sliders move
        $('#min-price-slider, #max-price-slider').on('input', function() { 
            let min = parseInt($('#min-price-slider').val()), max = parseInt($('#max-price-slider').val()); 
            if (min > max) [min, max] = [max, min]; 
            $('#price-range-display').text(`Price: ৳ ${min} - ৳ ${max}`); 
        });

        // Event listener for removing a single filter tag
    $(document).on('click', '.remove-filter', function() {
        const tag = $(this).closest('.filter-tag');
        const type = tag.data('filter-type');
        const value = tag.data('filter-value');

        switch(type) {
            case 'category':
            case 'subcategory':
            case 'animation':
                $(`a[data-id="${value}"]`).removeClass('active');
                break;
            case 'price':
                $('#min-price-slider').val(0);
                $('#max-price-slider').val(10000);
                $('#price-range-display').text(`Price: ৳ 0 - ৳ 10000`);
                break;
            case 'stock':
                $('#all-stock').prop('checked', true);
                break;
            case 'size':
                $(`.size-filter[value="${value}"]`).prop('checked', false);
                break;
             // --- START: NEW CASE FOR SORTING ---
            case 'sort':
                $('#sort-select-new').val('default');
                break;
            // --- END: NEW CASE FOR SORTING ---
        }
        loadProducts(true);
    });

    // Event listener for the "Clear All" button
    $('#clear-all-filters').on('click', function(e) {
        e.preventDefault();
        $('.main-category-filter, .subcategory-filter, .animation-category-filter').removeClass('active');
        $('#min-price-slider').val(0);
        $('#max-price-slider').val(10000);
        $('#price-range-display').text(`Price: ৳ 0 - ৳ 10000`);
        $('#all-stock').prop('checked', true);
        $('.size-filter').prop('checked', false);
        $('#sort-select-new').val('default');
        loadProducts(true);
    });
        
        // Infinite scroll loader
        $(window).scroll(function() { 
            if ($('#product-list').length > 0 && ($(window).scrollTop() + $(window).height() >= $('#product-list').offset().top + $('#product-list').height() - 500)) { 
                if (hasMorePages && !isLoading) loadProducts(); 
            } 
        });
    });
</script>

@endsection