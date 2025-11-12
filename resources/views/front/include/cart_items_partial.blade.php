@forelse($cart as $item)
    @if(isset($item['is_bundle']) && $item['is_bundle'])
        {{-- ======================= BUNDLE ITEM DISPLAY FOR SIDEBAR ======================= --}}
        <div class="cart-product-item" id="cart-item-{{ $item['rowId'] }}">
            <img src="{{ $item['image'] ?  $item['image'] : 'https://placehold.co/80x80' }}" alt="{{ $item['name'] }}">
            <div class="product-details">
                {{-- Use the URL key for the link --}}
                <a href="{{ $item['url'] }}" class="text-dark text-decoration-none">
                    <h6 class="mb-0">{{ $item['name'] }}</h6>
                </a>
                <small class="text-muted d-block">Combo Bundle</small>
                
                {{-- List the chosen sub-products in a compact format --}}
                <div class="small text-muted mt-1" style="font-size: 0.75rem; line-height: 1.2;">
                    @foreach($item['selected_products'] as $subProduct)
                        <div>- {{ \Illuminate\Support\Str::limit($subProduct['name'], 25) }} ({{ $subProduct['size'] }})</div>
                    @endforeach
                </div>

                <div class="d-flex align-items-center mt-2">
                    <div class="d-flex align-items-center border rounded-3 overflow-hidden me-3" style="width: 80px;">
                        <button class="btn btn-sm btn-light rounded-0 cart-quantity-btn" data-row-id="{{ $item['rowId'] }}" data-change="-1">-</button>
                        <span class="px-2 small cart-quantity-value">{{ $item['quantity'] }}</span>
                        <button class="btn btn-sm btn-light rounded-0 cart-quantity-btn" data-row-id="{{ $item['rowId'] }}" data-change="1">+</button>
                    </div>
                    <span class="price fw-bold">৳ {{ number_format($item['price'] * $item['quantity'], 2) }}</span>
                </div>
            </div>
            <button type="button" class="btn-close remove-cart-item" data-row-id="{{ $item['rowId'] }}" aria-label="Remove item"></button>
        </div>

    @else
        {{-- ======================= REGULAR ITEM DISPLAY FOR SIDEBAR ======================= --}}
        <div class="cart-product-item" id="cart-item-{{ $item['rowId'] }}">
            @if($item['image'])
                <img src="{{ $front_ins_url . 'public/uploads/' . $item['image'] }}" alt="{{ $item['name'] }}">
            @else
                <img src="https://placehold.co/80x80" alt="Placeholder Image">
            @endif
            <div class="product-details">
                {{-- Use the URL key here instead of slug --}}
                <a href="{{ $item['url'] ?? '#' }}" class="text-dark text-decoration-none">
                    <h6 class="mb-0">{{ $item['name'] }} - {{ $item['size'] }}</h6>
                </a>
                <small class="text-muted">Color: {{ $item['color'] }}</small>
                <div class="d-flex align-items-center mt-2">

                    <div class="d-flex align-items-center border rounded-3 overflow-hidden me-3" style="width: 80px;">
                        <button class="btn btn-sm btn-light rounded-0 cart-quantity-btn" data-row-id="{{ $item['rowId'] }}" data-change="-1">-</button>
                        <span class="px-2 small cart-quantity-value">{{ $item['quantity'] }}</span>
                        <button class="btn btn-sm btn-light rounded-0 cart-quantity-btn" data-row-id="{{ $item['rowId'] }}" data-change="1">+</button>
                    </div>

                    <span class="price fw-bold">৳ {{ number_format($item['price'] * $item['quantity'], 2) }}</span>
                </div>
            </div>
            <button type="button" class="btn-close remove-cart-item" data-row-id="{{ $item['rowId'] }}" aria-label="Remove item"></button>
        </div>
    @endif
@empty
<div class="text-center p-5">
    <i class="bi bi-cart-x fs-1 text-muted"></i>
    <p class="mt-3">Your cart is currently empty.</p>
</div>
@endforelse