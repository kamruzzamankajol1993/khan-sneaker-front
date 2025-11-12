@extends('front.master.master')
@section('title', 'My Wishlist')

@section('body')
<main>
    <section class="section">
        <div class="container">
            <div class="spotlight_user_profile_container">
                <div class="spotlight_user_profile_breadcrumb">
                    <a href="{{ route('home.index') }}">Home</a> > <a href="{{ route('dashboard.user') }}">Account</a> > Wishlist
                </div>

                <div class="row">
                    <div class="col-lg-3 col-md-4 mb-4">
                        @include('front.include.dashboardSidebar')
                    </div>

                    <div class="col-lg-9 col-md-8">
                        <div class="spotlight_user_profile_main-content">
                            <div class="spotlight_user_profile_main-header">
                                <h4>Wishlist</h4>
                            </div>

                            <div id="wishlist-container">
                                @forelse ($wishlistItems as $item)
                                    <div class="spotlight_user_profile_wishlist-card" id="wishlist-item-{{ $item->id }}">
                                        <div class="spotlight_user_profile_wishlist-item">
                                            <div class="spotlight_user_profile_product-info">
                                                @php
                                                    $product = $item->product;
                                                    $variant = $item->productVariant;
                                                    $image = optional($variant)->variant_image[0] ?? optional($product)->main_image[0] ?? null;
                                                @endphp
                                                <div style="position: relative;">
                                                    <img src="{{ $image ? $front_ins_url.'public/uploads/'.$image : 'https://placehold.co/80x80' }}" alt="{{ optional($product)->name }}">
                                                </div>
                                                <div class="spotlight_user_profile_product-details">
                                                    <p>{{ optional($product)->name }}</p>
                                                    <small>Size: {{ $item->size }}, Color: {{ optional($variant->color)->name ?? 'N/A' }}</small>
                                                    <small>{{ optional($product->brand)->name ?? 'Brand' }}</small>
                                                </div>
                                            </div>
                                            <div class="spotlight_user_profile_wishlist-actions">
                                                @php
                                                    $price = optional($product)->discount_price ?? optional($product)->base_price ?? 0;
                                                    $basePrice = optional($product)->base_price ?? 0;
                                                    $additionalPrice = optional($variant)->additional_price ?? 0;
                                                    $finalPrice = $price + $additionalPrice;
                                                @endphp
                                                <span class="spotlight_user_profile_product-price">
                                                    ৳ {{ number_format($finalPrice, 2) }}
                                                    @if(optional($product)->discount_price)
                                                    <span class="spotlight_user_profile_original-price">৳ {{ number_format($basePrice + $additionalPrice, 2) }}</span>
                                                    @endif
                                                </span>
                                                <button class="btn btn-sm btn-outline-secondary remove-wishlist-btn" data-id="{{ $item->id }}">
                                                    <i class="bi bi-trash-fill"></i>
                                                </button>
                                                <button class="btn btn-sm spotlight_user_profile_add-to-cart-btn move-to-cart-btn" data-id="{{ $item->id }}">
                                                    <i class="bi bi-cart-fill"></i> Add to cart
                                                </button>
                                            </div>
                                        </div>
                                    </div>
                                @empty
                                    <div class="alert alert-info text-center">
                                        <p class="mb-0">Your wishlist is empty.</p>
                                    </div>
                                @endforelse
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </section>
</main>
@endsection

@section('script')
<script>
$(document).ready(function() {
    // Handle REMOVE from wishlist
    $('#wishlist-container').on('click', '.remove-wishlist-btn', function() {
        const wishlistItemId = $(this).data('id');
        const card = $(`#wishlist-item-${wishlistItemId}`);

        Swal.fire({
            title: 'Are you sure?',
            text: "This will remove the item from your wishlist.",
            icon: 'warning',
            showCancelButton: true,
            confirmButtonColor: '#d33',
            confirmButtonText: 'Yes, remove it!'
        }).then((result) => {
            if (result.isConfirmed) {
                $.ajax({
                    url: '{{ route("wishlist.remove") }}',
                    method: 'POST',
                    data: { _token: '{{ csrf_token() }}', wishlist_id: wishlistItemId },
                    success: function(response) {
    if(response.success) {
        card.fadeOut(300, function() { $(this).remove(); });
        Swal.fire({ toast: true, position: 'top-end', icon: 'success', title: response.message, showConfirmButton: false, timer: 2000 });

        // Update the header counters
        if (response.count !== undefined) {
            $('#wishlist-count').text(response.count);
            $('#mobile-wishlist-count').text(response.count);
        }
    }
},
                    error: function(xhr) {
                        Swal.fire({ icon: 'error', title: 'Oops...', text: xhr.responseJSON.message || 'Could not remove item.' });
                    }
                });
            }
        });
    });

    // Handle MOVE TO CART from wishlist
    $('#wishlist-container').on('click', '.move-to-cart-btn', function() {
        const wishlistItemId = $(this).data('id');
        const card = $(`#wishlist-item-${wishlistItemId}`);
        const button = $(this);
        button.prop('disabled', true).html('<span class="spinner-border spinner-border-sm"></span>');

        $.ajax({
            url: '{{ route("wishlist.moveToCart") }}',
            method: 'POST',
            data: { _token: '{{ csrf_token() }}', wishlist_id: wishlistItemId },
            success: function(response) {
             if(response.success) {
        card.fadeOut(300, function() { $(this).remove(); });
        updateCartOffcanvas(); // Update the sidebar cart
        Swal.fire({
            toast: true,
            position: 'top-end',
            icon: 'success',
            title: response.message,
            showConfirmButton: false,
            timer: 2000
        });

        // Update the header counters
        if (response.count !== undefined) {
            $('#wishlist-count').text(response.count);
            $('#mobile-wishlist-count').text(response.count);
        }
    }
},
            error: function(xhr) {
                Swal.fire({ icon: 'error', title: 'Oops...', text: xhr.responseJSON.message || 'Could not move item to cart.' });
                button.prop('disabled', false).html('<i class="bi bi-cart-fill"></i> Add to cart');
            }
        });
    });
});
</script>
@endsection