<div class="container-fluid" id="quick-view-container-{{ $product->id }}">
    <div class="row">
        <div class="col-md-5">
            <img id="quick-view-image" src="{{ (is_array($product->main_image) && count($product->main_image) > 0) ? $front_ins_url .'public/uploads/' . $product->main_image[0] : 'https://placehold.co/400' }}" alt="{{ $product->name }}" class="img-fluid rounded-3 w-100">
        </div>

        <div class="col-md-7">
            <h3 class="fw-semibold">{{ $product->name }}</h3>
            <p class="text-muted">SKU: <span id="quick-view-sku">{{ $product->product_code }}</span></p>

            <div class="mb-3">
                @if($product->discount_price)
                    <span class="h4 fw-bold text-dark" id="quick-view-price">৳ {{ number_format($product->discount_price, 2) }}</span>
                    <del class="text-muted ms-2">৳ {{ number_format($product->base_price, 2) }}</del>
                @else
                    <span class="h4 fw-bold text-dark" id="quick-view-price">৳ {{ number_format($product->base_price, 2) }}</span>
                @endif
            </div>

            @if($product->variants->isNotEmpty() && $product->variants->first()->color)
                <div class="mb-3">
                    <h6 class="fw-semibold">Color: <span id="quick-view-color-name">{{ $product->variants->first()->color->name }}</span></h6>
                    <div class="d-flex gap-2">
                        @foreach($product->variants as $variant)
                            <div class="color-option {{ $loop->first ? 'active' : '' }}"
                                 style="background-color: {{ $variant->color->code }}; width: 35px; height: 35px; border-radius: 50%; cursor: pointer; border: 2px solid #ddd;"
                                 data-variant-id="{{ $variant->id }}"
                                 data-color-name="{{ $variant->color->name }}"
                                 data-additional-price="{{ $variant->additional_price }}"
                                 data-variant-sku="{{ $variant->variant_sku }}"
                                 data-sizes="{{ json_encode($variant->detailed_sizes) }}">
                            </div>
                        @endforeach
                    </div>
                </div>
            @endif

            <div class="mb-3">
                <h6 class="fw-semibold">Size: <span id="quick-view-size-name" class="text-dark">Select a size</span></h6>
                <div id="quick-view-size-container" class="d-flex gap-2 flex-wrap">
                    {{-- Size buttons will be dynamically inserted here --}}
                </div>
            </div>

           <div class="d-flex align-items-center gap-3">
    <div class="d-flex align-items-center border rounded-3 overflow-hidden">
        <button class="btn btn-light rounded-0" id="qv-quantity-minus">-</button>
        <span class="px-3" id="qv-quantity-value">1</span>
        <button class="btn btn-light rounded-0" id="qv-quantity-plus">+</button>
    </div>
    
    {{-- Add to Cart button now with icon and tooltip --}}
    <button class="btn btn-outline-dark" id="qv-add-to-cart" data-bs-toggle="tooltip" title="Add to Cart">
        <i class="bi bi-cart-plus "></i>
    </button>

    {{-- Wishlist button with tooltip enabled --}}
    <button class="btn btn-outline-danger" id="qv-add-to-wishlist" data-bs-toggle="tooltip" title="Add to Wishlist">
        <i class="bi bi-heart"></i>
    </button>

    {{-- Compare button with tooltip enabled --}}
    <button class="btn btn-outline-secondary" id="qv-add-to-compare" data-bs-toggle="tooltip" title="Add to Compare">
        <i class="bi bi-arrow-left-right"></i>
    </button>
</div>
            
        </div>
    </div>
</div>

<script>
$(document).ready(function() {
    
    const container = $('#quick-view-container-{{ $product->id }}');
    const BASE_PRODUCT_PRICE = {{ $product->discount_price ?? $product->base_price }};
    let selectedVariantId = null;
    let selectedSize = null;
    let currentStock = 0; // --- ADDED: Variable to hold current stock
 // --- NEW: Initialize Bootstrap Tooltips for the modal ---
    var tooltipTriggerList = [].slice.call(container.find('[data-bs-toggle="tooltip"]'));
    var tooltipList = tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });
    // --- END NEW ---
    // --- NEW: Handle Add to Compare ---
container.find('#qv-add-to-compare').on('click', function() {
    const $button = $(this);
    const productId = {{ $product->id }};

    $.ajax({
        url: '{{ route("compare.add") }}',
        method: 'POST',
        data: {
            _token: '{{ csrf_token() }}',
            product_id: productId
        },
        beforeSend: function() {
            $button.prop('disabled', true);
        },
        success: function(response) {
            Swal.fire({
                toast: true,
                position: 'top-end',
                icon: response.success ? 'success' : 'info',
                title: response.message,
                showConfirmButton: false,
                timer: 2500
            });
            
            // Update compare count in the header
            if(response.count !== undefined) {
                $('#compare-count').text(response.count);
            }
        },
        error: function(xhr) {
            Swal.fire({
                icon: 'error',
                title: 'Error',
                text: xhr.responseJSON.message || 'Could not add to compare list.'
            });
        },
        complete: function() {
            $button.prop('disabled', false);
        }
    });
});

    function updateSizes(sizes) {
        const sizeContainer = container.find('#quick-view-size-container');
        sizeContainer.empty();
        container.find('#quick-view-size-name').text('Select a size');
        selectedSize = null;
        currentStock = 0; // --- ADDED: Reset stock when sizes change
        container.find('#qv-quantity-value').text(1); // --- ADDED: Reset quantity to 1

        if (sizes && sizes.length > 0) {
            sizes.forEach(size => {
                const button = $('<button></button>')
                    .addClass('btn btn-outline-secondary btn-sm size-option')
                    .text(size.name)
                    .data('size-name', size.name)
                    .data('stock', size.quantity); // --- ADDED: Store stock quantity in the button
                
                if (size.quantity <= 0) {
                    button.prop('disabled', true).css('text-decoration', 'line-through');
                }
                sizeContainer.append(button);
            });
        } else {
            sizeContainer.html('<p class="text-danger small">This color is out of stock.</p>');
        }
    }

    // Handle color click
    container.find('.color-option').on('click', function() {
        const $this = $(this);
        container.find('.color-option').removeClass('active').css({'border-color': '#ddd', 'transform': 'scale(1)'});
        $this.addClass('active').css({'border-color': '#000', 'transform': 'scale(1.15)'});

        selectedVariantId = $this.data('variant-id');
        container.find('#quick-view-color-name').text($this.data('color-name'));
        container.find('#quick-view-sku').text($this.data('variant-sku') || '{{ $product->product_code }}');
        
        const additionalPrice = parseFloat($this.data('additional-price') || 0);
        const finalPrice = BASE_PRODUCT_PRICE + additionalPrice;
        container.find('#quick-view-price').text(`৳ ${finalPrice.toFixed(2)}`);
        
        updateSizes($this.data('sizes'));
    });

    // Handle size click
    container.find('#quick-view-size-container').on('click', '.size-option:not(:disabled)', function() {
        const $this = $(this);
        container.find('#quick-view-size-container .size-option').removeClass('active').css({'background-color': '', 'color': ''});
        $this.addClass('active').css({'background-color': '#212529', 'color': '#fff'});
        
        selectedSize = $this.data('size-name');
        currentStock = $this.data('stock'); // --- ADDED: Get stock from the clicked button
        
        container.find('#quick-view-size-name').text(selectedSize);
        container.find('#qv-quantity-value').text(1); // --- ADDED: Reset quantity to 1
    });

    // --- MODIFIED: Handle quantity with stock validation ---
    container.find('#qv-quantity-plus').on('click', () => {
        if (!selectedSize) {
            Swal.fire({ icon: 'warning', title: 'Select a Size', text: 'Please select a size first.' });
            return;
        }
        let qty = parseInt(container.find('#qv-quantity-value').text());
        if (qty >= currentStock) {
            Swal.fire({ icon: 'info', title: 'Stock Limit Reached', text: `Only ${currentStock} items are available for this size.` });
        } else {
            container.find('#qv-quantity-value').text(++qty);
        }
    });

    container.find('#qv-quantity-minus').on('click', () => {
        let qty = parseInt(container.find('#qv-quantity-value').text());
        if (qty > 1) {
            container.find('#qv-quantity-value').text(--qty);
        }
    });

    // Handle Add to Cart
    container.find('#qv-add-to-cart').on('click', function() {
         if (!selectedVariantId) {
            Swal.fire({ icon: 'warning', title: 'Hold on!', text: 'Please select a color first.' });
            return;
        }
        if (!selectedSize) {
            Swal.fire({ icon: 'warning', title: 'Almost there!', text: 'Please select a size.' });
            return;
        }
        // --- ADDED: Final stock check before adding to cart ---
        if (parseInt(container.find('#qv-quantity-value').text()) > currentStock) {
            Swal.fire({ icon: 'error', title: 'Quantity Exceeds Stock', text: `You can only add up to ${currentStock} items for this size.` });
            return;
        }

        const $button = $(this);
        const cartData = {
            productId: {{ $product->id }},
            variantId: selectedVariantId,
            size: selectedSize,
            quantity: parseInt(container.find('#qv-quantity-value').text()),
            _token: "{{ csrf_token() }}"
        };

        $.ajax({
            url: '{{ route("cart.add") }}',
            type: 'POST',
            data: cartData,
            beforeSend: function() {
                $button.prop('disabled', true).html('<span class="spinner-border spinner-border-sm"></span> Adding...');
            },
            success: function(response) {
                if (response.success) {
                    updateCartOffcanvas(); // This global function should be in your master layout
                    Swal.fire({
                        toast: true,
                        position: 'top-end',
                        icon: 'success',
                        title: response.message,
                        showConfirmButton: false,
                        timer: 3000
                    });

                    $('#quickViewModal').modal('hide');
                    const cartOffcanvas = new bootstrap.Offcanvas(document.getElementById('cartOffcanvas'));
                    cartOffcanvas.show();
                } else {
                    Swal.fire({ icon: 'error', title: 'Oops...', text: response.message || 'An error occurred.' });
                }
            },
            error: function(xhr) {
                Swal.fire({ icon: 'error', title: 'Request Failed', text: 'Could not add product to cart.' });
            },
            complete: function() {
                $button.prop('disabled', false).text('Add To Cart');
            }
        });
    });

    // --- Handle Add to Wishlist (no changes needed here) ---
    container.find('#qv-add-to-wishlist').on('click', function() {
        @auth
            if (!selectedVariantId) { Swal.fire({ icon: 'warning', title: 'Hold on!', text: 'Please select a color first.' }); return; }
            if (!selectedSize) { Swal.fire({ icon: 'warning', title: 'Almost there!', text: 'Please select a size.' }); return; }
            const $button = $(this);
            const wishlistData = {
                product_id: {{ $product->id }}, variant_id: selectedVariantId, size: selectedSize, _token: "{{ csrf_token() }}"
            };
            $.ajax({
                url: '{{ route("wishlist.add") }}', type: 'POST', data: wishlistData,
                beforeSend: function() { $button.prop('disabled', true).find('i').toggleClass('bi-heart-fill bi-arrow-clockwise'); },
                success: function(response) {
                    if (response.success) {
                        Swal.fire({ toast: true, position: 'top-end', icon: 'success', title: response.message, showConfirmButton: false, timer: 2000 });
                        if (response.count !== undefined) {
                            $('#wishlist-count').text(response.count);
                            $('#mobile-wishlist-count').text(response.count);
                        }
                    } else {
                         Swal.fire({ icon: 'info', title: 'Already Added', text: response.message });
                    }
                },
                error: function(xhr) { Swal.fire({ icon: 'error', title: 'Oops...', text: 'Something went wrong.' }); },
                complete: function() { $button.prop('disabled', false).find('i').toggleClass('bi-arrow-clockwise bi-heart-fill'); }
            });
        @else
            Swal.fire({
                title: 'Login Required', text: "You need to be logged in to add items to your wishlist.", icon: 'info',
                showCancelButton: true, confirmButtonText: 'Login or Register', cancelButtonText: 'Not Now'
            }).then((result) => {
                if (result.isConfirmed) {
                    const quickViewModalInstance = bootstrap.Modal.getInstance(document.getElementById('quickViewModal'));
                    if (quickViewModalInstance) { quickViewModalInstance.hide(); }
                    const signInOffcanvas = new bootstrap.Offcanvas(document.getElementById('signInOffcanvas'));
                    $('.modal-backdrop').remove();
                    $('body').removeAttr('style').removeClass('modal-open');
                    signInOffcanvas.show();
                }
            });
        @endauth
    });

    // Trigger click on the first color to initialize sizes
    container.find('.color-option.active').first().trigger('click');
});
</script>