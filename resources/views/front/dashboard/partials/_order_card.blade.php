<div class="spotlight_user_profile_order-card">
    <div class="spotlight_user_profile_order-card-header">
        <div>
            <span class="spotlight_user_profile_order-id">Order ID: #{{ $order->invoice_no }}</span>
        </div>
        <div class="d-flex align-items-center">
            <i class="bi bi-truck me-1 text-success"></i>
            <span class="spotlight_user_profile_order-delivery">{{ $order->delivery_type ?? 'Regular' }} Delivery</span>
        </div>
    </div>

    <div class="d-flex justify-content-between align-items-start">
        <div class="spotlight_user_profile_order-info">
            <i class="bi bi-house-door-fill"></i>
            <div>
                <div class="spotlight_user_profile_order-name">{{ $order->customer->name }}</div>
                <div class="spotlight_user_profile_order-details">{{ $order->customer->phone }}</div>
                <div class="spotlight_user_profile_order-details">{{ $order->shipping_address }}</div>
            </div>
        </div>
        <div class="spotlight_user_profile_order-date">
            Date: {{ \Carbon\Carbon::parse($order->created_at)->format('d-M-Y h:i A') }}
        </div>
    </div>

    <div class="spotlight_user_profile_order-footer">
        <div>
            <div>Amount Payable</div>
            <div class="spotlight_user_profile_amount">৳ {{ number_format($order->total_amount) }}
                @if($order->payment_status == 'paid')
                    <span class="text-success">(Paid)</span>
                @else
                    <span class="text-warning">(Unpaid)</span>
                @endif
            </div>
            {{-- Dynamically set a CSS class based on the order status for styling --}}
            @php
                $statusClass = Str::slug($order->status);
            @endphp
            <span class="spotlight_user_profile_status {{ $statusClass }}">{{ $order->status }}</span>
        </div>
        <div>
            {{-- <button class="btn btn-outline-dark spotlight_user_profile_btn">Order Again</button> --}}
            <button class="btn btn-outline-dark spotlight_user_profile_btn" onclick="window.location.href='{{ route('user.order.detail', base64_encode($order->id)) }}'">View Details</button>
        </div>
    </div>
</div>
