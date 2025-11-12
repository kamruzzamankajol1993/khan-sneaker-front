@extends('front.master.master')

@section('title', $offer->name ?? 'Special Offer')

@section('css')
<style>
    #loading-spinner { 
        display: none; 
        text-align: center; 
        padding: 20px 0; 
    }
    .offer-filter.active { 
        font-weight: bold; 
        color: #0d6efd !important; 
    }
     /* --- START: NEW CSS FOR FILTER TAGS --- */
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
    /* --- END: NEW CSS FOR FILTER TAGS --- */
</style>
@endsection

@section('body')
<main>
    <section class="section">
        <div class="container py-4">
            <h2 class="text-center mb-4">{{ $offer->title }}</h2>
            <div class="row">
                <div class="col-12 d-block d-md-none mb-3">
                    <button class="btn btn-dark w-100" type="button" data-bs-toggle="offcanvas" data-bs-target="#mobile-filter-menu">
                        <i class="bi bi-tags-fill"></i> View Other Offers
                    </button>
                </div>

                <div class="col-md-3 d-none d-md-block sticky-filter">
                    @include('front.offer.filter_sidebar')
                </div>

                <div class="col-md-9">
                    <div id="active-filters-container">
                        <div id="active-filters-list" class="d-inline">
                            </div>
                        <a href="#" id="clear-all-filters" class="ms-2">Clear All</a>
                    </div>
                    <div class="product-grid">
                        <div id="product-list" class="row row-cols-2 row-cols-sm-2 row-cols-lg-3 row-cols-xl-4 g-3"
                             data-base-offer-id="{{ $offer->id }}">
                            
                            @include('front.offer.bundle_card_partial', [
                                'bundleDeals' => $bundleDeals, 
                                'productsCollection' => $productsCollection
                            ])

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
            <div class="offcanvas-header">
                <h5 class="offcanvas-title">Other Offers</h5>
                <button type="button" class="btn-close" data-bs-dismiss="offcanvas" aria-label="Close"></button>
            </div>
            <div class="offcanvas-body">
                @include('front.offer.filter_sidebar')
            </div>
        </div>
    </section>
</main>
@endsection

@section('script')
{{-- START: UPDATED FILTERING SCRIPT --}}
<script>
$(document).ready(function() {
    let page = 2;
    let hasMorePages = {{ $bundleDeals->hasMorePages() ? 'true' : 'false' }};
    let isLoading = false;
    let currentRequest = null;

    // NEW: Function to build and display active filter tags
    function updateActiveFiltersDisplay() {
        const filtersList = $('#active-filters-list');
        const filtersContainer = $('#active-filters-container');
        filtersList.html('');
        let hasActiveFilters = false;

        // Check for a manually selected offer
        $('.offer-filter.active').each(function() {
            if ($(this).data('id') != $('#product-list').data('base-offer-id')) {
                const text = $(this).text();
                const id = $(this).data('id');
                filtersList.append(`<span class="filter-tag" data-filter-type="offer" data-filter-value="${id}">${text} <span class="remove-filter" title="Remove filter">&times;</span></span>`);
                hasActiveFilters = true;
            }
        });

        // Check for a price range filter
        const minPrice = $('#min-price-slider').val();
        const maxPrice = $('#max-price-slider').val();
        // Assuming your default max price on the slider is 20000
        if (minPrice > 0 || maxPrice < 20000) { 
            filtersList.append(`<span class="filter-tag" data-filter-type="price">Price: ৳ ${minPrice} - ৳ ${maxPrice} <span class="remove-filter" title="Remove filter">&times;</span></span>`);
            hasActiveFilters = true;
        }

        if (hasActiveFilters) {
            filtersContainer.slideDown(200);
        } else {
            filtersContainer.slideUp(200);
        }
    }

    // This function correctly gets the active filters or the page's base offer
    function getFilters() {
        let filters = {
            min_price: $('#min-price-slider').val(),
            max_price: $('#max-price-slider').val()
        };
        const activeOffer = $('.offer-filter.active').data('id');

        if (activeOffer) {
            filters.offer_id = activeOffer;
        } else {
            filters.offer_id = $('#product-list').data('base-offer-id');
        }
        return filters;
    }

    function loadProducts(reset = false) {
        if (isLoading) return;
        if (reset) {
            page = 1;
            $('#product-list').html('');
        }

        updateActiveFiltersDisplay(); // NEW: Update tags on every load

        isLoading = true;
        $('#loading-spinner').show();
        if (currentRequest) currentRequest.abort();

        currentRequest = $.ajax({
            url: `{{ route('offer.filter') }}?page=${page}`,
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

    // Initial call for tags on page load
    updateActiveFiltersDisplay();

    // On-scroll loader
    $(window).scroll(function() {
        if ($('#product-list').length && !isLoading && hasMorePages) {
            const listBottom = $('#product-list').offset().top + $('#product-list').height();
            const screenBottom = $(window).scrollTop() + $(window).height();
            if (screenBottom >= listBottom - 500) {
                loadProducts();
            }
        }
    });

    // Sidebar filter listeners
    $(document).on('click', '.offer-filter', function(e) { e.preventDefault(); if ($(this).hasClass('active')) { $(this).removeClass('active'); } else { $('.offer-filter').removeClass('active'); $(this).addClass('active'); } loadProducts(true); });
    $('#price-filter-btn').on('click', () => loadProducts(true));
    $('#min-price-slider, #max-price-slider').on('input', function() { let minPrice = parseInt($('#min-price-slider').val()); let maxPrice = parseInt($('#max-price-slider').val()); if (minPrice > maxPrice) { [minPrice, maxPrice] = [maxPrice, minPrice]; } $('#price-range-display').text(`Price: ৳ ${minPrice} - ৳ ${maxPrice}`); });

    // NEW: Listeners for removing/clearing tags
    $(document).on('click', '.remove-filter', function() {
        const tag = $(this).closest('.filter-tag');
        const type = tag.data('filter-type');
        const value = tag.data('filter-value');

        if (type === 'offer') {
            $(`a.offer-filter[data-id="${value}"]`).removeClass('active');
        } else if (type === 'price') {
            $('#min-price-slider').val(0);
            $('#max-price-slider').val(20000);
            $('#price-range-display').text(`Price: ৳ 0 - ৳ 20000`);
        }
        loadProducts(true);
    });

    $('#clear-all-filters').on('click', function(e) {
        e.preventDefault();
        $('.offer-filter').removeClass('active');
        $('#min-price-slider').val(0);
        $('#max-price-slider').val(20000);
        $('#price-range-display').text(`Price: ৳ 0 - ৳ 20000`);
        loadProducts(true);
    });
});
</script>
{{-- END: UPDATED FILTERING SCRIPT --}}
@endsection