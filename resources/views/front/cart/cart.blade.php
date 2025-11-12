@extends('front.master.master')

@section('title')
Your Cart
@endsection

@section('css')
<style>
    /* Add a style for the loading state */
    #main-cart-body .spinner-border {
        width: 3rem;
        height: 3rem;
    }
</style>
@endsection

@section('body')
 <section class="section">
            <div class="container">
                <header class="spotlight_cart_progress_header">
                    <div class="container">
                        <nav class="d-flex justify-content-center align-items-center fw-semibold">
                            <span class="spotlight_cart_progress_item">SHOPPING CART</span>
                            <span class="spotlight_cart_progress_item opacity-50">CHECKOUT</span>
                            <span class="spotlight_cart_progress_item opacity-50">ORDER COMPLETE</span>
                        </nav>
                    </div>
                </header>

                <div class="container spotlight_cart_container">
                    {{-- <div class="alert alert-success d-flex align-items-center small py-2 rounded-pill" role="alert">
                        <i class="bi bi-cart3 me-2"></i>
                        <span>Add **৳ 1,901.0** to cart and get free shipping!</span>
                    </div> --}}

                    @include('flash_message')

                    <div class="row g-4">
                        <div class="col-12 col-lg-8">
                            <div class="spotlight_cart_summary_card">
                                <h5 class="fw-semibold">Product</h5>
                                <div class="table-responsive">
                                    <table class="spotlight_cart_table">
                                        <thead>
                                            <tr>
                                                <th class="text-start">PRODUCT</th>
                                                <th>PRICE</th>
                                                <th>QUANTITY</th>
                                                <th>SUBTOTAL</th>
                                                <th></th> 
                                            </tr>
                                        </thead>
                                        <tbody id="main-cart-body">
                                            {{-- Cart items will be loaded here by JavaScript --}}
                                            <tr>
                                                <td colspan="4" class="text-center py-5">
                                                    <div class="spinner-border" role="status">
                                                        <span class="visually-hidden">Loading...</span>
                                                    </div>
                                                </td>
                                            </tr>
                                        </tbody>
                                    </table>
                                </div>
                            </div>

                        </div>

                        <div class="col-12 col-lg-4">
                             <div class="spotlight_cart_summary_card mb-4">
                        <h5 class="fw-semibold">Cart Totals</h5>
                        <div class="spotlight_cart_total_row border-bottom">
                            <span class="fw-semibold">Subtotal</span>
                            <span class="fw-semibold" id="cart-page-subtotal">৳ 0.00</span>
                        </div>

                        {{-- DYNAMIC COUPON DISPLAY --}}
                        <div id="coupon-applied-section" class="spotlight_cart_total_row border-bottom text-success" style="display: none;">
                            <span class="fw-semibold">Discount</span>
                            <span class="fw-semibold" id="cart-page-discount">- ৳ 0.00</span>
                            <a href="#" id="remove-coupon-btn" class="text-danger ms-2 small">[Remove]</a>
                        </div>
                      
                        <div class="spotlight_cart_total_row border-top pt-3">
                            <h6 class="fw-bold mb-0">Total</h6>
                            <h6 class="fw-bold mb-0" id="cart-page-total">৳ 0.00</h6>
                        </div>

                               {{-- DYNAMIC COUPON SECTION --}}
                        <div id="coupon-section" class="mt-4">
                            <form id="coupon-form" class="d-flex">
                                <input type="text" id="coupon-code" class="form-control me-2" placeholder="Coupon code">
                                <button type="submit" class="btn btn-outline-secondary">Apply Coupon</button>
                            </form>
                            <div id="coupon-message" class="mt-2 small"></div>
                        </div>
                        <div class="text-center text-muted small bg-light p-2 rounded mt-3">
    <i class="bi bi-info-circle me-1"></i>
    Shipping charges calculated at checkout
</div>
                        {{-- DYNAMIC CHECKOUT BUTTON --}}
                        <button id="proceed-to-checkout-btn" class="btn btn-dark spotlight_cart_action_button mt-3">Proceed To Checkout</button>
                    </div>
                        </div>
                        <div class="col-lg-8 col-sm-12 col-12">
                                                        <div class="spotlight_cart_interest_card">
                                <h5 class="fw-semibold">You May Be Interested In...</h5>
                                <div class="row row-cols-2 row-cols-md-4 g-3 mt-3">
                                   {{-- This section is now dynamic --}}
                                   @forelse($suggestedProducts as $product)
                                        <div class="col">
                                            <div class="product-card card h-100">
                                                @php
                                                    $image = (is_array($product->main_image) && count($product->main_image) > 0)
                                                                ? $front_ins_url . 'public/uploads/' . $product->main_image[0]
                                                                : 'https://placehold.co/400x400';
                                                @endphp
                                                <a href="{{ route('product.show', $product->slug) }}">
                                                    <img src="{{ $image }}" class="card-img-top" alt="{{ $product->name }}">
                                                </a>
                                                <div class="product-details-body">
                                                    <h5 class="product-title mb-1">{{ Str::limit($product->name, 20) }}</h5>
                                                    <p class="price-tag mb-2">
                                                        @if($product->discount_price)
                                                            <del class="text-muted">৳ {{ number_format($product->base_price) }}</del>
                                                            <span class="fw-bold">৳ {{ number_format($product->discount_price) }}</span>
                                                        @else
                                                            <span class="fw-bold">৳ {{ number_format($product->base_price) }}</span>
                                                        @endif
                                                    </p>
                                                    <a href="#" class="btn btn-primary btn-add-cart w-100" data-product-id="{{ $product->id }}">Add to Cart</a>
                                                </div>
                                            </div>
                                        </div>
                                    @empty
                                        <div class="col-12">
                                            <p>No other products to suggest at the moment.</p>
                                        </div>
                                    @endforelse
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </section>
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
$(document).ready(function() {
    
     // --- HELPER FUNCTION TO UPDATE TOTALS ---
    function updateCartTotals(response) {
        $('#cart-page-subtotal').text('৳ ' + response.subtotal);
        if (response.coupon && parseFloat(response.discount.replace(/,/g, '')) > 0) {
            $('#cart-page-discount').text('- ৳ ' + response.discount);
            $('#coupon-applied-section').show();
            $('#coupon-section').hide();
        } else {
            $('#coupon-applied-section').hide();
            $('#coupon-section').show();
            $('#coupon-code').val(''); // Clear input
        }
        $('#cart-page-total').text('৳ ' + response.total);
    }

    // --- FUNCTION TO LOAD/REFRESH THE MAIN CART PAGE CONTENT ---
    function loadMainCart() {
        $.ajax({
            url: '{{ route("cart.main_content") }}',
            type: 'GET',
            success: function(response) {
                $('#main-cart-body').html(response.html);
                updateCartTotals(response);
            },
            error: function() {
                $('#main-cart-body').html('<tr><td colspan="4" class="text-center text-danger py-5">Could not load cart. Please try again.</td></tr>');
            }
        });
    }

    // --- INITIAL CART LOAD ---
    loadMainCart();

    $(document.body).on('cart-updated', function() {
        loadMainCart();
    });

      // --- COUPON FORM SUBMISSION ---
    $('#coupon-form').on('submit', function(e) {
        e.preventDefault();
        const code = $('#coupon-code').val();
        if (!code) return;

        $.ajax({
            url: '{{ route("cart.applyCoupon") }}',
            method: 'POST',
            data: { _token: '{{ csrf_token() }}', coupon_code: code },
            success: function(response) {
                Swal.fire({ toast: true, position: 'top-end', icon: 'success', title: response.message, showConfirmButton: false, timer: 2000 });
                $('#main-cart-body').html(response.html);
                updateCartTotals(response);
            },
            error: function(xhr) {
                Swal.fire({ icon: 'error', title: 'Oops...', text: xhr.responseJSON.message });
            }
        });
    });

    // --- REMOVE COUPON ---
    $('#remove-coupon-btn').on('click', function(e) {
        e.preventDefault();
        $.ajax({
            url: '{{ route("cart.removeCoupon") }}',
            method: 'POST',
            data: { _token: '{{ csrf_token() }}' },
            success: function(response) {
                Swal.fire({ toast: true, position: 'top-end', icon: 'info', title: response.message, showConfirmButton: false, timer: 2000 });
                $('#main-cart-body').html(response.html);
                updateCartTotals(response);
            }
        });
    });

    // --- PROCEED TO CHECKOUT BUTTON ---
    $('#proceed-to-checkout-btn').on('click', function(e) {
        e.preventDefault();
        
        @auth
            // If user is logged in, redirect to checkout
            window.location.href = '{{ route("user.checkout") }}';
        @else
            // If user is a guest, open the login/register modal
             // If user is a guest, open the login/register offcanvas
        const signInOffcanvas = new bootstrap.Offcanvas(document.getElementById('signInOffcanvas')); // <-- CORRECT
        
        signInOffcanvas.show();
        @endauth
    });

    // --- EVENT HANDLERS FOR UPDATE AND REMOVE ---
    // Using event delegation since cart items are loaded dynamically
     // --- UPDATED EVENT HANDLER FOR REMOVING ITEMS ---
    $('#main-cart-body').on('click', '.remove-main-cart-item', function() {
        const rowId = $(this).data('row-id');

        Swal.fire({
            title: 'Are you sure?',
            text: "Do you want to remove this item from your cart?",
            icon: 'warning',
            showCancelButton: true,
            confirmButtonColor: '#d33',
            cancelButtonColor: '#3085d6',
            confirmButtonText: 'Yes, remove it!',
            cancelButtonText: 'Cancel'
        }).then((result) => {
            if (result.isConfirmed) {
                // If the user confirms, proceed with the removal
                $.ajax({
                    url: '{{ route("cart.main.remove") }}',
                    type: 'POST',
                    data: { _token: '{{ csrf_token() }}', rowId: rowId },
                    success: function(response) {
                        // On success, call the global function to update the sidebar.
                        // This will also trigger the 'cart-updated' event,
                        // which automatically refreshes the main cart table.
                        updateCartOffcanvas();

                        Swal.fire({
                           toast: true,
                           position: 'top-end',
                           icon: 'success',
                           title: 'Item removed successfully!',
                           showConfirmButton: false,
                           timer: 2000
                        });
                    },
                    error: function() {
                        Swal.fire(
                          'Error!',
                          'Could not remove the item. Please try again.',
                          'error'
                        )
                    }
                });
            }
        });
    });

    $('#main-cart-body').on('click', '.update-main-cart-item', function() {
        const rowId = $(this).data('row-id');
        const action = $(this).data('action');
        const quantityElement = $(this).closest('div').find('span');
        let currentQuantity = parseInt(quantityElement.text());
        
        let newQuantity = (action === 'increase') ? currentQuantity + 1 : currentQuantity - 1;

        if (newQuantity < 1) return; // Prevent quantity from going below 1
        
        quantityElement.text(newQuantity); // Optimistic UI update

        $.ajax({
            url: '{{ route("cart.main.update") }}',
            type: 'POST',
            data: { _token: '{{ csrf_token() }}', rowId: rowId, quantity: newQuantity },
            success: function(response) {
                $('#main-cart-body').html(response.html);
                updateCartTotals(response); // This is the fix
                updateCartOffcanvas(); // Also update the sidebar cart
            },
            error: function() {
                //alert('Could not update quantity. Please try again.');
                quantityElement.text(currentQuantity); // Revert on error
                // Show a SweetAlert error message
                Swal.fire({
                  icon: 'error',
                  title: 'Update Failed',
                  text: 'Could not update the quantity. Please try again.'
                });
            }
        });
    });

});
</script>
@endsection
