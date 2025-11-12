@extends('front.master.master')
@section('title', 'User Orders')
@section('body')
<main>
    <section class="section">
        <div class="container py-4">
            <div class="row">
                <!-- Left Sidebar -->
                <div class="col-lg-3 col-md-4 mb-4">
                    @include('front.include.dashboardSidebar')
                </div>

                <!-- Main Content Area -->
                <!-- Main Content Area -->
                            <div class="col-lg-9 col-md-8">
                                <div class="spotlight_user_profile_main-content">
    <div class="spotlight_user_profile_main-header">
        <h4>My Orders</h4>
    </div>

    @php
        // Define the statuses and their display order for the tabs
        $statuses = ['pending','waiting', 'ready to ship', 'shipping', 'delivered', 'cancelled'];
    @endphp

    <!-- Filter Tabs -->
    <ul class="nav nav-tabs spotlight_user_profile_filter-tabs" id="myOrderTab" role="tablist">
        <li class="nav-item" role="presentation">
            <button class="nav-link active" id="all-tab" data-bs-toggle="tab" data-bs-target="#all-orders-pane" type="button" role="tab" aria-controls="all-orders-pane" aria-selected="true">All</button>
        </li>
        @foreach($statuses as $status)
        <li class="nav-item" role="presentation">
            <button class="nav-link" id="{{ Str::slug($status) }}-tab" data-bs-toggle="tab" data-bs-target="#{{ Str::slug($status) }}-pane" type="button" role="tab" aria-controls="{{ Str::slug($status) }}-pane" aria-selected="false">
                {{ $status }} ({{ $ordersByStatus->get($status, collect())->count() }})
            </button>
        </li>
        @endforeach
    </ul>

    <div class="tab-content" id="myOrderTabContent">
        <!-- All Orders Tab Content -->
        <div class="tab-pane fade show active" id="all-orders-pane" role="tabpanel" aria-labelledby="all-tab">
            @php $allOrders = $ordersByStatus->flatten(); @endphp
            @forelse($allOrders as $order)
                @include('front.dashboard.partials._order_card', ['order' => $order])
            @empty
                <div class="alert alert-info mt-3 text-center">
                    <p class="mb-0">You haven't placed any orders yet.</p>
                </div>
            @endforelse
        </div>

        <!-- Dynamic Status Tabs Content -->
        @foreach($statuses as $status)
        <div class="tab-pane fade" id="{{ Str::slug($status) }}-pane" role="tabpanel" aria-labelledby="{{ Str::slug($status) }}-tab">
            @forelse($ordersByStatus->get($status, collect()) as $order)
                @include('front.dashboard.partials._order_card', ['order' => $order])
            @empty
                <div class="alert alert-info mt-3 text-center">
                    <p class="mb-0">You have no orders with the status "{{ $status }}".</p>
                </div>
            @endforelse
        </div>
        @endforeach
    </div>
</div>

                            </div>
            </div>
        </div>
    </section>
</main>
@endsection
