@extends('front.master.master')

@section('title', 'Order Details #' . $order->invoice_no)

@section('body')
<main>
    <section class="section">
        <div class="container">
            <div class="spotlight_user_profile_container">
                <div class="spotlight_user_profile_breadcrumb">
                    <a href="{{ route('home.index') }}">Home</a> > 
                    <a href="{{ route('dashboard.user') }}">Account</a> > 
                    <a href="{{ route('user.order.list') }}">Orders</a> > 
                    View Order #{{ $order->invoice_no }}
                </div>

                <div class="row">
                    <!-- Left Sidebar -->
                    <div class="col-lg-3 col-md-4 mb-4">
                        @include('front.include.dashboardSidebar')
                    </div>

                    <!-- Main Content Area -->
                    <div class="col-lg-9 col-md-8">
                        <div class="spotlight_user_profile_main-content">
                            <div class="spotlight_user_profile_order-details-header">
                                <h4>View Order #{{ $order->invoice_no }}</h4>
                                <a class="btn btn-dark spotlight_user_profile_btn" href="{{ route('user.order.list') }}">
                                    <i class="bi bi-arrow-left"></i> Back to Orders
                                </a>
                            </div>

                            {{-- Dynamic Order Tracking Timeline --}}
                            <div class="spotlight_user_profile_timeline">
                                @forelse($order->trackingHistory as $history)
                                <div class="spotlight_user_profile_timeline-item">
                                    <div class="spotlight_user_profile_timeline-date">
                                        {{ \Carbon\Carbon::parse($history->created_at)->format('M d') }}<br>
                                        {{ \Carbon\Carbon::parse($history->created_at)->format('h:i A') }}
                                    </div>
                                    <div class="spotlight_user_profile_timeline-icon active"></div>
                                    <div class="spotlight_user_profile_timeline-content">
                                        <h5>{{ $history->status }}</h5>
                                        <p>Your order status has been updated to {{ strtolower($history->status) }}.</p>
                                    </div>
                                </div>
                                @empty
                                <div class="alert alert-info">No tracking information available for this order yet.</div>
                                @endforelse
                            </div>
                            
                            <div class="row mt-4">
                                <div class="col-12">
                                    <h5 class="spotlight_user_profile_main-header">Order Items</h5>
                                    @foreach($order->orderDetails as $detail)
                                    <div class="spotlight_user_profile_section-card mb-3">
                                        <div class="d-flex justify-content-between align-items-center">
                                            <div class="d-flex align-items-center">
                                                @php
                                                    $image = $detail->product && is_array($detail->product->main_image) ? $detail->product->main_image[0] : null;
                                                @endphp
                                                <img src="{{ $image ? $front_ins_url. 'public/uploads/' .$image : 'https://placehold.co/60x60' }}" alt="{{ $detail->product->name ?? 'Product' }}" class="me-3 rounded" style="width: 60px; height: 60px; object-fit: cover;">
                                                <div>
                                                    <p class="m-0 fw-bold">{{ $detail->product->name ?? 'Product not found' }}</p>
                                                    <small class="text-muted">Size: {{ $detail->size }}, Color: {{ $detail->color }}</small>
                                                    <p class="m-0 text-muted" style="font-size: 0.9em;">
                                                        ৳ {{ number_format($detail->unit_price, 2) }} &times; {{ $detail->quantity }}
                                                    </p>
                                                </div>
                                            </div>
                                            <div>
                                                <span class="badge bg-success">{{ $order->status }}</span>
                                            </div>
                                        </div>
                                    </div>
                                    @endforeach
                                </div>
                            </div>
<div class="text-center mt-5 mb-4">
                            {{-- UPDATE THIS BUTTON --}}
                            <button class="btn btn-dark spotlight_user_profile_btn" id="reorder-btn" data-order-id="{{ $order->id }}">
                                Create another order with these items
                            </button>
                        </div>
                            <div class="row mt-4">
                                <div class="col-12">
                                    <h5 class="spotlight_user_profile_main-header">Shipping Address</h5>
                                    <div class="spotlight_user_profile_section-card d-flex justify-content-between align-items-center">
                                        <div>
                                            <h6>{{ $order->customer->name }}</h6>
                                            <p class="m-0 text-muted">{{ $order->customer->phone }}</p>
                                            <p class="m-0 text-muted">{{ $order->shipping_address }}</p>
                                        </div>
                                        @if($order->status == 'pending')
                                            <button class="btn btn-outline-danger spotlight_user_profile_btn" id="cancel-order-btn" data-order-id="{{ $order->id }}">Cancel Order</button>
                                        @endif
                                    </div>
                                </div>
                            </div>

                            <div class="row mt-4">
                                <div class="col-12">
                                    <div class="spotlight_user_profile_section-card">
                                        <div class="row">
                                            <div class="col-7">
                                                <p class="m-0 fw-bold">Order ID</p>
                                                <p class="m-0 fw-bold">Order At</p>
                                                <p class="m-0 fw-bold">Subtotal</p>
                                                <p class="m-0 fw-bold">Shipping Cost</p>
                                                <p class="m-0 fw-bold">Discount Applied</p>
                                                <p class="m-0 fw-bold mt-3">Amount Payable</p>
                                                <p class="m-0 fw-bold">Payment Status</p>
                                            </div>
                                            <div class="col-5 text-end">
                                                <p class="m-0 fw-bold">#{{ $order->invoice_no }}</p>
                                                <p class="m-0 fw-bold">{{ \Carbon\Carbon::parse($order->created_at)->format('d M Y, h:i A') }}</p>
                                                <p class="m-0 fw-bold">৳ {{ number_format($order->subtotal, 2) }}</p>
                                                <p class="m-0 fw-bold">৳ {{ number_format($order->shipping_cost, 2) }}</p>
                                                <p class="m-0 text-success">-৳ {{ number_format($order->discount, 2) }}</p>
                                                <p class="m-0 fw-bold mt-3">৳ {{ number_format($order->total_amount, 2) }}</p>
                                                <p class="m-0 fw-bold {{ $order->payment_status == 'paid' ? 'text-success' : 'text-danger' }}">
                                                    {{ ucfirst($order->payment_status) }}
                                                </p>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            </div>

                            <div class="text-center mt-4">
    {{-- UPDATE THIS BUTTON TO BE A LINK --}}
    <a href="{{ route('user.order.invoice', ['id' => base64_encode($order->id)]) }}" class="btn spotlight_user_profile_download-btn" target="_blank">
        <i class="bi bi-download me-2"></i>Download your Invoice
    </a>
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
    $('#cancel-order-btn').on('click', function() {
        const orderId = $(this).data('order-id');

        Swal.fire({
            title: 'Are you sure?',
            text: "You won't be able to revert this action!",
            icon: 'warning',
            showCancelButton: true,
            confirmButtonColor: '#d33',
            cancelButtonColor: '#3085d6',
            confirmButtonText: 'Yes, cancel it!'
        }).then((result) => {
            if (result.isConfirmed) {
                const button = $(this);
                button.prop('disabled', true).html('<span class="spinner-border spinner-border-sm"></span> Cancelling...');

                $.ajax({
                    url: '{{ route("user.order.cancel") }}',
                    method: 'POST',
                    data: {
                        _token: '{{ csrf_token() }}',
                        order_id: orderId
                    },
                    success: function(response) {
                        if (response.success) {
                            Swal.fire({
                                icon: 'success',
                                title: 'Cancelled!',
                                text: response.message,
                                showConfirmButton: false,
                                timer: 2000
                            });

                            button.fadeOut();
                            $('.order-status-badge').removeClass('bg-success').addClass('bg-danger').text('Cancelled');
                            
                            const timeline = $('.spotlight_user_profile_timeline');
                            const now = new Date();
                            const formattedDate = now.toLocaleString('default', { month: 'short', day: 'numeric' }) + '<br>' + now.toLocaleString('default', { hour: 'numeric', minute: 'numeric', hour12: true });
                            
                            const newTimelineItem = `
                                <div class="spotlight_user_profile_timeline-item">
                                    <div class="spotlight_user_profile_timeline-date">${formattedDate}</div>
                                    <div class="spotlight_user_profile_timeline-icon active"></div>
                                    <div class="spotlight_user_profile_timeline-content">
                                        <h5>Cancelled</h5>
                                        <p>Your order has been cancelled.</p>
                                    </div>
                                </div>`;
                            timeline.append(newTimelineItem);
                        }
                    },
                    error: function(xhr) {
                        Swal.fire({
                            icon: 'error',
                            title: 'Oops...',
                            text: xhr.responseJSON.message || 'Something went wrong!'
                        });
                        button.prop('disabled', false).text('Cancel Order');
                    }
                });
            }
        });
    });

    // --- NEW SCRIPT FOR RE-ORDER BUTTON ---
    $('#reorder-btn').on('click', function() {
        const orderId = $(this).data('order-id');
        const button = $(this);
        button.prop('disabled', true).html('<span class="spinner-border spinner-border-sm"></span> Adding to Cart...');

        $.ajax({
            url: '{{ route("user.reorder") }}',
            method: 'POST',
            data: {
                _token: '{{ csrf_token() }}',
                order_id: orderId
            },
            success: function(response) {
                if(response.success) {
                    Swal.fire({
                        icon: 'success',
                        title: 'Success!',
                        text: response.message,
                        timer: 2000,
                        timerProgressBar: true,
                        willClose: () => {
                             window.location.href = response.redirect_url;
                        }
                    });
                }
            },
            error: function(xhr) {
                 Swal.fire({
                    icon: 'error',
                    title: 'Oops...',
                    text: xhr.responseJSON.message || 'Something went wrong!'
                });
                button.prop('disabled', false).text('Create another order with these items');
            }
        });
    });
});
</script>
@endsection

