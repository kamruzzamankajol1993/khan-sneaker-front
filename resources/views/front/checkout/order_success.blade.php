@extends('front.master.master')
@section('title', 'Order Successful')

@section('body')
<main>
    <section class="section">
        <div class="container py-5">
            <div class="row justify-content-center">
                <div class="col-md-8 col-lg-6 text-center">
                     <div class="card shadow-sm">
                        <div class="card-body p-4 p-md-5">
                            <i class="bi bi-check-circle-fill text-success" style="font-size: 5rem;"></i>
                            <h1 class="mt-3">Thank You!</h1>
                            <p class="lead">Your order has been placed successfully.</p>
                            <hr class="my-4">
                            <p class="mb-1">Your Order ID is:</p>
                            <h4 class="fw-bold">#{{ $order->invoice_no }}</h4>
                            {{-- <p class="small text-muted mt-3">We have sent a confirmation email to <strong>{{ $order->customer->email }}</strong> with your order details.</p> --}}
                            <div class="mt-4">
                                <a href="{{ route('shop.show') }}" class="btn btn-outline-secondary">Continue Shopping</a>
                                <a href="{{ route('user.order.list') }}" class="btn btn-dark">View My Orders</a>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </section>
</main>
@endsection

