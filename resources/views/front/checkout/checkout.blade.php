@extends('front.master.master')
@section('title', 'Checkout')

@section('css')
<style>
    /* Custom Checkbox Styles */
    .custom-checkbox-card { border: 1px solid #dee2e6; border-radius: 0.5rem; padding: 1rem; cursor: pointer; transition: all 0.2s ease-in-out; position: relative; }
    .custom-checkbox-card:hover { border-color: #000; background-color: #f8f9fa;}
    .custom-checkbox-card input[type="radio"] { opacity: 0; position: absolute; }
    .custom-checkbox-card.selected { border-color: #0d6efd; background-color: #e7f1ff; box-shadow: 0 0 0 2px rgba(13, 110, 253, 0.25); }
    .custom-checkbox-card .icon { font-size: 1.5rem; }
    .custom-checkbox-card .title { font-weight: 600; }
    .custom-checkbox-card .description { font-size: 0.85rem; color: #6c757d; }
    /* Add this to your existing <style> block */
.custom-checkbox-card.disabled-option {
    opacity: 0.6;
    cursor: not-allowed;
    background-color: #f8f9fa !important;
}
.custom-checkbox-card.disabled-option:hover {
    border-color: #dee2e6; /* Prevents hover effect */
    box-shadow: none;
}
</style>
@endsection

@section('body')
<main>
    <section class="section">
        <div class="container">
            <div class="spotlight_checkout_container">

                {{-- Section to display validation errors and session messages --}}
                @if ($errors->any())
                    <div class="alert alert-danger">
                        <ul>
                            @foreach ($errors->all() as $error)
                                <li>{{ $error }}</li>
                            @endforeach
                        </ul>
                    </div>
                @endif
                @if (session('error'))
                    <div class="alert alert-danger">{{ session('error') }}</div>
                @endif
                @if (session('success'))
                     <div class="alert alert-success">{{ session('success') }}</div>
                @endif

                {{-- MODIFIED: Added method and action to the form tag --}}
                <form id="checkout-form" method="POST" action="{{ route('place.order') }}">
                    @csrf
                    {{-- ADDED: Hidden input to hold the shipping cost --}}
                    <input type="hidden" name="shipping_cost" id="shipping_cost_input" value="0">
                    
                    <div class="row">
                        <div class="col-lg-7 mb-4">
                            <h3 class="spotlight_checkout_section-title">BILLING DETAILS</h3>
                             <div class="row">
                                <div class="col-md-6">
                                    <div class="spotlight_checkout_form-group">
                                        <label for="name">Full Name *</label>
                                        <input type="text" id="name" class="form-control" value="{{ Auth::user()->name }}" readonly>
                                    </div>
                                </div>
                                <div class="col-md-6">
                                     <div class="spotlight_checkout_form-group">
                                        <label for="phone">Phone *</label>
                                        <input type="tel" id="phone" class="form-control" value="{{ Auth::user()->phone }}" readonly>
                                    </div>
                                </div>
                            </div>
                            
                            <div class="spotlight_checkout_form-group mt-3">
                                <label class="mb-2">Select Shipping Address *</label>
                                @forelse($addresses as $address)
                                <label class="d-block">
                                    <div class="form-check border p-3 rounded-3 mb-2 custom-checkbox-card" data-name="shipping_address">
                                        <input class="form-check-input shipping-address-radio" type="radio" name="shipping_address_id" id="address{{ $address->id }}" value="{{ $address->id }}" {{ $address->is_default ? 'checked' : '' }}>
                                        <div class="w-100">
                                            <strong>{{ $address->name }}</strong> ({{ $address->address_type }})<br>
                                            <small>{{ $address->address }}</small><br>
                                            <small>{{ $address->phone }}</small>
                                        </div>
                                    </div>
                                </label>
                                @empty
                                <div class="alert alert-warning">
                                    You have no saved addresses. Please <a href="{{ route('dashboard.profile.address.update') }}">add an address</a> first.
                                </div>
                                @endforelse
                                <a href="{{ route('dashboard.profile.address.update') }}" class="btn btn-sm btn-outline-secondary mt-2"><i class="bi bi-plus-circle"></i> Add or Manage Addresses</a>
                            </div>

                            <div class="spotlight_checkout_form-group mt-4">
                                <label for="order-notes">Order notes (optional)</label>
                                <textarea id="order-notes" name="notes" class="form-control" rows="4" placeholder="Notes about your order..."></textarea>
                            </div>
                        </div>

                        <div class="col-lg-5">
                            <div class="spotlight_checkout_order-summary">
                                <div class="mb-4">
                                    <h5 class="mb-3">Delivery Type</h5>
                                    <p class="text-muted small mb-2">Express delivery available only inside Dhaka .</p>
                                    <div class="row g-2">
                                        <div class="col-6">
                                            <label class="custom-checkbox-card" data-name="delivery_type">
                                                <input type="radio" name="delivery_type" value="regular" checked>
                                                <div class="d-flex align-items-center"><i class="bi bi-truck icon me-3"></i><div><div class="title">Regular</div><div class="description">3-5 days</div></div></div>
                                            </label>
                                        </div>
                                        <div class="col-6">
                                            <label id="express-delivery-option" class="custom-checkbox-card" data-name="delivery_type">
                                                <input id="express-delivery-input" type="radio" name="delivery_type" value="express">
                                                <div class="d-flex align-items-center"><i class="bi bi-lightning-charge-fill icon me-3"></i><div><div class="title">Express</div><div class="description">1-2 days</div></div></div>
                                            </label>
                                        </div>
                                    </div>
                                </div>
                                <h3 class="spotlight_checkout_section-title">YOUR ORDER</h3>
                                <div class="table-responsive">
                                    <table class="table table-borderless">
                                        <thead>
                                            <tr><th>PRODUCT</th><th class="text-end">SUBTOTAL</th></tr>
                                        </thead>
                                        <tbody>
                                            @foreach($cartItems as $item)
                                            <tr>
                                                <td>{{ Str::limit($item['name'], 25) }} &times; {{ $item['quantity'] }}</td>
                                                <td class="text-end fw-bold">৳ {{ number_format($item['price'] * $item['quantity'], 2) }}</td>
                                            </tr>
                                            @endforeach
                                        </tbody>
                                    </table>
                                </div>

                                <div class="spotlight_checkout_subtotal"><span>Subtotal</span><span>৳ {{ number_format($subtotal, 2) }}</span></div>
                                @if($coupon)
                                <div class="spotlight_checkout_subtotal text-success"><span>Discount ({{ $coupon->code }})</span><span>- ৳ {{ number_format($discount, 2) }}</span></div>
                                @endif
                                <div class="spotlight_checkout_subtotal"><span>Shipping</span><span id="shipping-charge-text">Select an address</span></div>
                                <div class="spotlight_checkout_total"><span>Total</span><span id="grand-total-text">৳ {{ number_format($subtotal - $discount, 2) }}</span></div>
                                


                                <div class="my-4">
                                    <h5 class="mb-3">Payment Method</h5>
                                    <div class="row g-2">
                                        <div class="col-6">
                                            <label class="custom-checkbox-card" data-name="payment_method"><input type="radio" name="payment_method" value="cod" checked><div class="d-flex align-items-center"><i class="bi bi-cash-coin icon me-3"></i><div><div class="title">Cash on Delivery</div><div class="description">Pay upon arrival</div></div></div></label>
                                        </div>
                                        <div class="col-6">
                                            <label class="custom-checkbox-card disabled-option" data-name="payment_method">
                                                <input type="radio" name="payment_method" value="sslcommerz" disabled>
                                                <div class="d-flex align-items-center">
                                                    <i class="bi bi-credit-card-2-front-fill icon me-3"></i>
                                                    <div>
                                                        <div class="title">SSLCommerz</div>
                                                        <div class="description">Card, MFS, Banking</div>
                                                    </div>
                                                </div>
                                            </label>
                                        </div>
                                         <div class="col-6 mt-2">
                                            <label class="custom-checkbox-card" data-name="payment_method"><input type="radio" name="payment_method" value="bkash"><div class="d-flex align-items-center"><i class="bi bi-wallet2 icon me-3"></i><div><div class="title">bKash</div><div class="description">Pay with bKash</div></div></div></label>
                                        </div>
                                    </div>
                                </div>
                                <p class="spotlight_checkout_privacy-text small">Your personal data will be used to process your order...</p>
                                <button type="submit" class="spotlight_checkout_place-order-btn" id="place-order-btn" disabled>Place Order</button>
                            </div>
                        </div>
                    </div>
                </form>
            </div>
        </div>
    </section>
</main>
@endsection

@section('script')
<script>
$(document).ready(function() {
    let subtotalWithDiscount = {{ $subtotal - $discount }};
    let shippingCharge = 0;

    function updateTotals() {
        const grandTotal = subtotalWithDiscount + shippingCharge;
        $('#shipping-charge-text').text(`৳ ${shippingCharge.toFixed(2)}`);
        $('#grand-total-text').text(`৳ ${grandTotal.toFixed(2)}`);

        // MODIFIED: Update the hidden input's value
        $('#shipping_cost_input').val(shippingCharge);

        $('#place-order-btn').prop('disabled', false);
    }

    function getShippingCharge(addressId) {
    if (!addressId) {
        $('#shipping-charge-text').text('Select an address');
        $('#place-order-btn').prop('disabled', true);
        return;
    }

    // --- START: NEW LOGIC FOR EXPRESS DELIVERY ---
    const expressOption = $('#express-delivery-option');
    const expressInput = $('#express-delivery-input');
    const regularInput = $('input[name="delivery_type"][value="regular"]');
    
    // Get the full address text from the selected radio button's label
    const selectedRadio = $(`.shipping-address-radio[value="${addressId}"]`);
    const addressText = selectedRadio.closest('.form-check').find('small').first().text();
    
    // Check if the address is in Dhaka
    const isDhaka = addressText.toLowerCase().includes('dhaka');

    if (isDhaka) {
        // Enable Express Delivery
        expressOption.removeClass('disabled-option');
        expressInput.prop('disabled', false);
    } else {
        // Disable Express Delivery
        expressOption.addClass('disabled-option');
        expressInput.prop('disabled', true);
        
        // If Express was selected, switch back to Regular
        if (expressInput.is(':checked')) {
            regularInput.prop('checked', true).trigger('change');
        }
    }
    // --- END: NEW LOGIC FOR EXPRESS DELIVERY ---

    $('#shipping-charge-text').html('<span class="spinner-border spinner-border-sm"></span>');
    $('#place-order-btn').prop('disabled', true);

    $.ajax({
        url: '{{ route("get.shipping.charge") }}',
        method: 'POST',
        data: { _token: '{{ csrf_token() }}', address_id: addressId },
        success: function(response) {
            if(response.success) {
                shippingCharge = parseFloat(response.shipping_charge);
                updateTotals();
            }
        },
        error: function(xhr) {
            shippingCharge = 130; // Default fallback
            updateTotals();
        }
    });
}

    $('.custom-checkbox-card').on('click', function() {
        // ADDED: If the card is disabled, do nothing
        if ($(this).hasClass('disabled-option')) {
            return;
        }
        
        const radioName = $(this).find('input[type="radio"]').attr('name');
        $(`.custom-checkbox-card input[name="${radioName}"]`).closest('.custom-checkbox-card').removeClass('selected');
        $(this).addClass('selected').find('input[type="radio"]').prop('checked', true).trigger('change');
    });
    
    $('input[type="radio"]:checked').closest('.custom-checkbox-card').addClass('selected');

    $('.shipping-address-radio').on('change', function() {
        getShippingCharge($(this).val());
    });

    const defaultAddressId = $('.shipping-address-radio:checked').val();
    if(defaultAddressId){
        getShippingCharge(defaultAddressId);
    } else if ($('.shipping-address-radio').length > 0) {
        $('.shipping-address-radio').first().prop('checked', true).trigger('change');
    } else {
        $('#shipping-charge-text').text('Please add an address');
        $('#place-order-btn').prop('disabled', true);
    }
    
    // REMOVED: The entire AJAX form submission block is gone.
});
</script>
@endsection