@extends('front.master.master')
@section('title', 'Compare Products')

@section('body')
<main>
    <section class="section">
        <div class="container py-5">
            <div class="d-flex justify-content-between align-items-center mb-4">
                <h2 class="h3">Compare Products</h2>
                @if($products->isNotEmpty())
                <a href="{{ route('compare.clear') }}" id="clear-compare-btn" class="btn btn-sm btn-outline-danger">
                    <i class="bi bi-x-lg"></i> Clear All
                </a>
                @endif
            </div>

            @if($products->isEmpty())
                <div class="text-center py-5">
                    <i class="bi bi-arrow-left-right fs-1 text-muted"></i>
                    <h4 class="mt-3">Your compare list is empty.</h4>
                    <p class="text-muted">Add products to compare their features side-by-side.</p>
                    <a href="{{ route('shop.show') }}" class="btn btn-dark mt-2">Continue Shopping</a>
                </div>
            @else
                <div class="table-responsive">
                    <table class="table table-bordered text-center align-middle">
                        <tbody>
                            <tr class="bg-light">
                                <th class="p-3" style="width: 20%;">Features</th>
                                @foreach($products as $product)
                                    <td class="p-3" style="width: 20%;">
                                        <button class="btn btn-sm btn-danger float-end remove-compare-btn" data-id="{{ $product->id }}" title="Remove">&times;</button>
                                        @php
                                            $image = is_array($product->main_image) ? $product->main_image[0] : null;
                                        @endphp
                                        <a href="{{ route('product.show', $product->slug) }}">
                                            <img style="width: 100px; height: 100px;" src="{{ $image ? $front_ins_url.'public/uploads/'.$image : 'https://placehold.co/150x150' }}" alt="{{ $product->name }}" class="img-fluid mb-2">
                                            <h6>{{ $product->name }}</h6>
                                        </a>
                                    </td>
                                @endforeach
                            </tr>
                            <tr>
                                <th class="text-start p-3">Price</th>
                                @foreach($products as $product)
                                    <td>
                                        @if($product->discount_price)
                                            <span class="fw-bold fs-5">৳ {{ number_format($product->discount_price) }}</span>
                                            <del class="text-muted ms-2">৳ {{ number_format($product->base_price) }}</del>
                                        @else
                                            <span class="fw-bold fs-5">৳ {{ number_format($product->base_price) }}</span>
                                        @endif
                                    </td>
                                @endforeach
                            </tr>
                             <tr>
                                <th class="text-start p-3">Brand</th>
                                @foreach($products as $product)
                                    <td>{{ optional($product->brand)->name ?? 'N/A' }}</td>
                                @endforeach
                            </tr>
                            <tr>
                                <th class="text-start p-3">Category</th>
                                @foreach($products as $product)
                                    <td>{{ optional($product->category)->name ?? 'N/A' }}</td>
                                @endforeach
                            </tr>
                            <tr>
                                <th class="text-start p-3">Availability</th>
                                @foreach($products as $product)
                                    <td>
                                        @if($product->variants->sum(fn($v) => array_sum(array_column($v->sizes, 'quantity'))) > 0)
                                            <span class="badge bg-success">In Stock</span>
                                        @else
                                            <span class="badge bg-danger">Out of Stock</span>
                                        @endif
                                    </td>
                                @endforeach
                            </tr>
                            <tr>
                                <th class="text-start p-3">Description</th>
                                @foreach($products as $product)
                                    <td class="small text-start">{{ Str::limit(strip_tags($product->description), 150) }}</td>
                                @endforeach
                            </tr>
                            <tr>
                                <th></th>
                                @foreach($products as $product)
                                    <td>
                                        <a href="{{ route('product.show', $product->slug) }}" class="btn btn-dark">View Product</a>
                                    </td>
                                @endforeach
                            </tr>
                        </tbody>
                    </table>
                </div>
            @endif
        </div>
    </section>
</main>
@endsection

@section('script')
<script>
$(document).ready(function() {
    $('.remove-compare-btn').on('click', function() {
    const productId = $(this).data('id');

    // Show confirmation dialog first
    Swal.fire({
        title: 'Are you sure?',
        text: "Do you want to remove this product?",
        icon: 'warning',
        showCancelButton: true,
        confirmButtonColor: '#d33',
        cancelButtonColor: '#3085d6',
        confirmButtonText: 'Yes, remove it!'
    }).then((result) => {
        // If the user confirms, then proceed with the AJAX call
        if (result.isConfirmed) {
            $.ajax({
                url: '{{ route("compare.remove") }}',
                method: 'POST',
                data: {
                    _token: '{{ csrf_token() }}',
                    product_id: productId
                },
                success: function(response) {
                    if (response.success) {
                        Swal.fire({
                            // toast: true,
                            // position: 'top-end',
                            icon: 'success',
                            title: response.message,
                            showConfirmButton: false,
                            timer: 1000
                        });
                        // Reload the page to show updated compare list
                        setTimeout(() => location.reload(), 1000);
                    }
                }
            });
        }
    });
});

       // --- ADD THIS NEW CODE BLOCK FOR THE CLEAR ALL CONFIRMATION ---
    $('#clear-compare-btn').on('click', function(e) {
        e.preventDefault(); // Prevent the link from navigating immediately
        const url = $(this).attr('href'); // Get the URL from the link

        Swal.fire({
            title: 'Are you sure?',
            text: "This will remove all products from your compare list.",
            icon: 'warning',
            showCancelButton: true,
            confirmButtonColor: '#d33',
            cancelButtonColor: '#3085d6',
            confirmButtonText: 'Yes, clear it!'
        }).then((result) => {
            if (result.isConfirmed) {
                // If the user confirms, navigate to the clear URL
                window.location.href = url;
            }
        });
    });
    // --- END OF NEW CODE BLOCK ---
});
</script>
@endsection
