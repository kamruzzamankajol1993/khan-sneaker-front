@forelse ($cart as $item)
    @if(isset($item['is_bundle']) && $item['is_bundle'])
        {{-- ======================= BUNDLE ITEM DISPLAY ======================= --}}
        <tr class="main-cart-item">
            {{-- Main Bundle Product Info --}}
            <td class="text-start" data-label="PRODUCT">
                <div class="d-flex align-items-center">
                    <img src="{{ $item['image'] ?? 'https://placehold.co/100x100' }}"
                         alt="{{ $item['name'] }}" class="spotlight_cart_item_image me-3">
                    <div class="spotlight_cart_item_details">
                        <a href="{{ $item['url'] }}" class="text-decoration-none text-dark">
                            <h6 class="mb-0 fw-semibold">{{ $item['name'] }}</h6>
                        </a>
                        <p class="text-muted small mb-0">Combo Bundle</p>
                    </div>
                </div>
            </td>
            {{-- Bundle Price --}}
            <td data-label="PRICE" class="fw-semibold">৳{{ number_format($item['price'], 2) }}</td>
            {{-- Bundle Quantity --}}
            <td data-label="QUANTITY">
                <div class="spotlight_cart_item_quantity">
                    <button class="btn btn-light update-main-cart-item" data-row-id="{{ $item['rowId'] }}" data-action="decrease">-</button>
                    <span class="px-2">{{ $item['quantity'] }}</span>
                    <button class="btn btn-light update-main-cart-item" data-row-id="{{ $item['rowId'] }}" data-action="increase">+</button>
                </div>
            </td>
            {{-- Bundle Subtotal --}}
            <td data-label="SUBTOTAL" class="fw-semibold">
                <div class="cart_subtotal">
                ৳{{ number_format($item['price'] * $item['quantity'], 2) }}
                <button class="btn btn-danger btn-sm remove-main-cart-item ms-2" data-row-id="{{ $item['rowId'] }}" title="Remove item">
                    <i class="bi bi-x-lg"></i>
                </button>
                </div>
            </td>
        </tr>

        {{-- Loop and display selected products for the bundle --}}
        @foreach($item['selected_products'] as $subProduct)
        <tr class="spotlight_cart_nested_item">
            <td data-label="PRODUCT" class="text-start">
                <div class="d-flex align-items-center">
                    <img src="{{ $subProduct['image'] ?? 'https://placehold.co/50x50' }}"
                         alt="{{ $subProduct['name'] }}"
                         class="spotlight_cart_nested_item_image me-2">
                    <div class="spotlight_cart_nested_item_details">
                        <h6 class="mb-0 text-muted small">{{ $subProduct['name'] }}</h6>
                        @if(!empty($subProduct['size']))
                        <p class="text-muted small mb-0">Size: {{ $subProduct['size'] }}</p>
                        @endif
                        @if(!empty($subProduct['color']))
                        <p class="text-muted small mb-0">Color: {{ $subProduct['color'] }}</p>
                        @endif
                    </div>
                </div>
            </td>
            <td data-label="PRICE" class="fw-semibold text-center text-muted"><small>৳ {{ number_format($subProduct['price'], 2) }}</small></td>
            <td data-label="QUANTITY" class="text-center text-muted">{{ $item['quantity'] }}</td>
            <td data-label="SUBTOTAL" class="fw-semibold text-center text-muted"><small>৳ {{ number_format($subProduct['price'] * $item['quantity'], 2) }}</small></td>
            <td></td> {{-- Empty cell for alignment --}}
        </tr>
        @endforeach

    @else
        {{-- ======================= REGULAR ITEM DISPLAY ======================= --}}
        <tr class="main-cart-item">
            <td class="text-start cart_product" data-label="PRODUCT">
                 <div class="d-flex align-items-center">
                    <img src="{{$front_ins_url . 'public/uploads/' . $item['image']  ?? 'https://placehold.co/100x100' }}"
                         alt="{{ $item['name'] }}" class="spotlight_cart_item_image me-3">
                    <div class="spotlight_cart_item_details">
                        <a href="{{ $item['url'] ?? '#' }}" class="text-decoration-none text-dark">
                            <h6 class="mb-0 fw-semibold">{{ $item['name'] }}</h6>
                        </a>
                        <p class="text-muted small mb-0">Size: {{ $item['size'] }}</p>
                        @if(!empty($item['color']) && $item['color'] !== 'N/A')
                            <p class="text-muted small mb-0">Color: {{ $item['color'] }}</p>
                        @endif
                    </div>
                </div>
            </td>
            <td data-label="PRICE" class="fw-semibold">৳{{ number_format($item['price'], 2) }}</td>
            <td data-label="QUANTITY">
                <div class="spotlight_cart_item_quantity">
                     <button class="btn btn-light update-main-cart-item" data-row-id="{{ $item['rowId'] }}" data-action="decrease">-</button>
                     <span class="px-2">{{ $item['quantity'] }}</span>
                     <button class="btn btn-light update-main-cart-item" data-row-id="{{ $item['rowId'] }}" data-action="increase">+</button>
                </div>
            </td>
            <td data-label="SUBTOTAL" class="fw-semibold">
                <div class="cart_subtotal">
                ৳{{ number_format($item['price'] * $item['quantity'], 2) }}
                <button class="btn btn-danger btn-sm remove-main-cart-item ms-2" data-row-id="{{ $item['rowId'] }}" title="Remove item">
                    <i class="bi bi-x-lg"></i>
                </button>
                </div>
            </td>

        </tr>
    @endif
@empty
    <tr>
        <td colspan="5" class="text-center py-5">
            <h5 class="mb-3">Your cart is currently empty.</h5>
            <a href="{{ route('shop.show') }}" class="btn btn-dark">Return to shop</a>
        </td>
    </tr>
@endforelse