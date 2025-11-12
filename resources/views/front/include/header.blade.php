    <!-- Desktop & Tablet Header (Hidden on mobile) -->
<style>
    .search-container {
        position: relative;
    }
    .search-results-popup {
        display: none;
        position: absolute;
        top: 100%;
        left: 0;
        right: 0;
        background-color: #fff;
        border: 1px solid #e0e0e0;
        border-top: none;
        border-radius: 0 0 0.375rem 0.375rem;
        box-shadow: 0 5px 15px rgba(0,0,0,0.1);
        z-index: 1050; /* Ensure it's above other content */
        max-height: 400px;
        overflow-y: auto;
    }
    .search-result-item {
        display: flex;
        align-items: center;
        padding: 0.75rem 1rem;
        border-bottom: 1px solid #f0f0f0;
        text-decoration: none;
        color: #212529;
        transition: background-color 0.2s ease-in-out;
    }
    .search-result-item:last-child { border-bottom: none; }
    .search-result-item:hover { background-color: #f8f9fa;color: black }
    .search-result-item img {
        width: 50px;
        height: 50px;
        object-fit: cover;
        border-radius: 0.25rem;
        margin-right: 1rem;
    }
    .search-result-info .price {
        font-size: 0.9em;
    }
    /* Specific adjustment for mobile search container */
    .mobile-search-bar .search-container {
        width: 100%;
    }
    /* This adds a smooth transition to the icons */
/* This adds a smooth transition ONLY to the icons on the right */
.header-bottom .righti .nav-link {
    transition: transform 0.2s ease-in-out, color 0.2s ease-in-out;
}

/* This applies the zoom and color change ONLY when you hover on the right-side icons */
.header-bottom .righti .nav-link:hover {
    color: black !important; 
    transform: scale(1.2); 
}
</style>
    <header class="d-none d-lg-block sticky-header">
        <!-- Top Section -->
        <div class="header-top p-3 d-flex align-items-center" style="background-color: {{ $headerColor }} !important;">
            <div class="container d-flex justify-content-between align-items-center">
                <!-- Logo -->
                <a class="logo-container" href="{{route('home.index')}}">
                    <img src="{{$front_ins_url}}{{$front_logo_name}}" alt="Spotlighy Attires">
                </a>

                <!-- Search Bar -->
                 <!-- DYNAMIC SEARCH BAR -->
            <div class="search-container">
                <div class="input-group">
                    <input type="text" id="product-search-input" class="form-control" placeholder="Search for products" autocomplete="off">
                    <span class="input-group-text" id="desktop-search-icon" style="cursor: pointer;"><i class="bi bi-search"></i></span>
                </div>
                <!-- Search Results Popup Container -->
                <div id="search-results-container" class="search-results-popup">
                    {{-- Results will be injected here by JavaScript --}}
                </div>
            </div>

                <!-- Support -->
                @if(isset($supportInfo))
                <div class="d-flex align-items-center">
                    <i class="bi bi-headset me-2 fs-4"></i>
                    <div>
                        <div class="fw-bold">{{ $supportInfo->title }}</div>
                        <div>{{ $supportInfo->phone }}</div>
                    </div>
                </div>
                @endif
            </div>
        </div>
        <!-- Bottom Section -->
        <div class="header-bottom p-3">
            <div class="container d-flex justify-content-between align-items-center">
                <!-- Left Side: All Categories & Sub-menu items -->
                <div class="d-flex align-items-center">
                    <button class="btn btn-all-categories me-3" type="button" data-bs-toggle="offcanvas"
                        data-bs-target="#categoriesOffcanvas" aria-controls="categoriesOffcanvas">
                        <i class="bi bi-list me-2"></i> All Category
                    </button>
                    <!-- Added the Menu link here -->
                    <a class="nav-link text-dark mx-2 d-none d-xl-block" href="{{route('shop.show')}}" >All Product</a>
                    @if(isset($menuItems) && $menuItems->count() > 0)
    @foreach($menuItems as $item)
        <a class="nav-link text-dark mx-2 d-none d-xl-block" href="{{ url($item->route) }}">{{ $item->name }}</a>
    @endforeach
@endif
  <a class="nav-link text-dark mx-2 d-none d-xl-block" href="#" >About Us</a>
  <a class="nav-link text-dark mx-2 d-none d-xl-block" href="#" >Contact Us</a>
                </div>

                <!-- Right Side: Icons -->
                <div class="d-flex align-items-center righti">
                    <!-- Updated User icon to trigger the new offcanvas -->

                    @if (Auth::check())
<a class="nav-link text-dark me-3" href="{{route('dashboard.user')}}" >
                        <i class="bi bi-person-circle fs-4"></i>
                    </a>
                    @else
                    <a class="nav-link text-dark me-3" href="#" data-bs-toggle="offcanvas"
                        data-bs-target="#signInOffcanvas" aria-controls="signInOffcanvas">
                        <i class="bi bi-person-circle fs-4"></i>
                    </a>
                    @endif
                    @if (Auth::check())
<a class="nav-link text-dark me-3" href="{{route('wishlist.index')}}">
    <i class="bi bi-heart fs-4"></i>
    <span id="wishlist-count" class="badge rounded-pill bg-dark" style="position: relative;top: -13px;left: -8px;font-size: 0.6em; padding: .35em .5em;">{{ Auth::user()->wishlist->count() }}</span>
</a>
@else
<a class="nav-link text-dark me-3" href="#" data-bs-toggle="offcanvas"
    data-bs-target="#signInOffcanvas" aria-controls="signInOffcanvas">
    <i class="bi bi-heart fs-4"></i>
    <span id="wishlist-count" class="badge rounded-pill bg-dark" style="position: relative;top: -13px;left: -8px;font-size: 0.6em; padding: .35em .5em;">0</span>
</a>
@endif
                    <a class="nav-link text-dark me-3" href="{{route('compare.index')}}">
    <i class="bi bi-arrow-left-right fs-4"></i>
    <span id="compare-count" class="badge rounded-pill bg-dark" style="position: relative;top: -13px;left: -8px;font-size: 0.6em; padding: .35em .5em;">{{ count(Session::get('compare', [])) }}</span>
</a>
                    <!-- Updated Cart icon to trigger the new offcanvas -->
                    <a class="nav-link text-dark" href="#" data-bs-toggle="offcanvas" data-bs-target="#cartOffcanvas"
                        aria-controls="cartOffcanvas">
                        <i class="bi bi-cart fs-4"></i>
                        <span id="desktop-cart-count" class="badge rounded-pill bg-dark" style="position: relative;top: -13px;left: -8px;font-size: 0.6em; padding: .35em .5em;">0</span>

                    </a>
                </div>
            </div>
        </div>
    </header>


    <!-- Mobile Header (Hidden on desktop/tablet) -->
    <header class="d-lg-none sticky-header">
        <!-- Top Section -->
        <nav class="navbar navbar-dark p-3">
            <div class="container-fluid">
                <button class="navbar-toggler border-0" type="button" data-bs-toggle="offcanvas"
                    data-bs-target="#mobileOffcanvas" aria-controls="mobileOffcanvas">
                    <span class="navbar-toggler-icon"></span>
                </button>
                <a class="navbar-brand mx-auto" href="{{route('home.index')}}">
                    <img src="{{$front_ins_url}}{{$front_mobile_version_logo}}" class="mobile_img" alt="Random Store">
                </a>
                <!-- Updated User icon to trigger the new offcanvas -->
                <a class="nav-link text-light" href="#" data-bs-toggle="offcanvas" data-bs-target="#signInOffcanvas"
                    aria-controls="signInOffcanvas">
                    <i class="bi bi-person-circle fs-4"></i>
                </a>
            </div>
        </nav>
        <!-- Bottom Section: Search -->
         <!-- Bottom Section: DYNAMIC MOBILE SEARCH -->
    <div class="mobile-search-bar">
        <form class="d-flex" onsubmit="return false;">
            <div class="input-group search-container">
                <input id="mobile-product-search-input" class="form-control rounded-pill" type="search" placeholder="Search for products" aria-label="Search" autocomplete="off">
                <span class="input-group-text">
                    <i class="bi bi-search"></i>
                </span>
                <!-- Mobile Search Results Popup Container -->
                <div id="mobile-search-results-container" class="search-results-popup"></div>
            </div>
        </form>
    </div>
    </header>

    <!-- Offcanvas for Desktop/Tablet Categories -->
    <div class="offcanvas offcanvas-start" tabindex="-1" id="categoriesOffcanvas" aria-labelledby="categoriesOffcanvasLabel">
    <div class="offcanvas-header bg-dark text-white">
        <h5 class="offcanvas-title" id="categoriesOffcanvasLabel">All Categories</h5>
        <button type="button" class="btn-close btn-close-white" data-bs-dismiss="offcanvas" aria-label="Close"></button>
    </div>
    <div class="offcanvas-body p-0">
        <div class="list-group list-group-flush">

            @if(isset($sidebarCategories))
                @foreach($sidebarCategories as $category)
                    {{-- Check if the category has any visible children --}}
                    @if($category->children->isNotEmpty())
                        <a class="list-group-item list-group-item-action d-flex justify-content-between align-items-center has-submenu"
                           data-bs-toggle="collapse" href="#submenu-{{ $category->id }}" role="button" aria-expanded="false"
                           aria-controls="submenu-{{ $category->id }}">
                           {{-- You can add icons here if you store them in the database --}}
                           {{ $category->name }} <i class="bi bi-chevron-right ms-auto"></i>
                        </a>
                        <div class="collapse" id="submenu-{{ $category->id }}">
                            @foreach($category->children as $childCategory)
                                {{-- Assuming child categories also use the 'category.show' route --}}
                                <a href="{{route('category.show', $childCategory->slug)}}" class="list-group-item list-group-item-action ps-5">{{ $childCategory->name }}</a>
                            @endforeach
                        </div>
                    @else
                        {{-- This is a parent category with no children --}}
                        <a href="{{route('category.show', $category->slug)}}" class="list-group-item list-group-item-action d-flex justify-content-between align-items-center">
                           {{ $category->name }} <i class="bi bi-chevron-right ms-auto"></i>
                        </a>
                    @endif
                @endforeach
            @endif

        </div>
    </div>
</div>

    <!-- New Offcanvas for Desktop Menu -->
    <div class="offcanvas offcanvas-start" tabindex="-1" id="menuOffcanvas" aria-labelledby="menuOffcanvasLabel">
        <div class="offcanvas-header bg-dark text-white">
            <h5 class="offcanvas-title" id="menuOffcanvasLabel">Menu</h5>
            <button type="button" class="btn-close btn-close-white" data-bs-dismiss="offcanvas"
                aria-label="Close"></button>
        </div>
        <div class="offcanvas-body p-0">
            <div class="list-group list-group-flush">
                <a href="{{route('home.index')}}" class="list-group-item list-group-item-action">Home</a>
                <a href="#" class="list-group-item list-group-item-action">About Us</a>
                <a href="#" class="list-group-item list-group-item-action">Contact</a>
            </div>
        </div>
    </div>

    <!-- Offcanvas for Mobile Menu -->
    <div class="offcanvas offcanvas-start" tabindex="-1" id="mobileOffcanvas" aria-labelledby="mobileOffcanvasLabel">
        <div class="offcanvas-header bg-dark text-white">
            <h5 class="offcanvas-title" id="mobileOffcanvasLabel">Main Menu</h5>
            <button type="button" class="btn-close btn-close-white" data-bs-dismiss="offcanvas"
                aria-label="Close"></button>
        </div>
        <div class="offcanvas-body p-0">
            <!-- Tabbed navigation -->
            <nav>
                <div class="nav nav-tabs" id="nav-tab" role="tablist">
                    <button class="nav-link active" id="nav-categories-tab" data-bs-toggle="tab"
                        data-bs-target="#nav-categories" type="button" role="tab" aria-controls="nav-categories"
                        aria-selected="true">CATEGORIES</button>
                    <button class="nav-link" id="nav-menu-tab" data-bs-toggle="tab" data-bs-target="#nav-menu"
                        type="button" role="tab" aria-controls="nav-menu" aria-selected="false">MENU</button>
                </div>
            </nav>
            <div class="tab-content" id="nav-tabContent">
                <!-- Categories Tab Content -->
                <div class="tab-pane fade show active" id="nav-categories" role="tabpanel"
                    aria-labelledby="nav-categories-tab">
                    <div class="list-group list-group-flush">
                       @if(isset($sidebarCategories))
                @foreach($sidebarCategories as $category)
                    @if($category->children->isNotEmpty())
                        <a class="list-group-item list-group-item-action d-flex justify-content-between align-items-center has-submenu"
                           data-bs-toggle="collapse" href="#mobile-submenu-{{ $category->id }}" role="button" aria-expanded="false"
                           aria-controls="mobile-submenu-{{ $category->id }}">
                            {{-- You can add an icon field to your category table for this --}}
                            <i class="bi bi-tag me-2"></i> {{ $category->name }} <i class="bi bi-chevron-right ms-auto"></i>
                        </a>
                        <div class="collapse" id="mobile-submenu-{{ $category->id }}">
                            @foreach($category->children as $childCategory)
                                {{-- Assuming child categories also use the 'category.show' route --}}
                                <a href="{{route('category.show', $childCategory->slug)}}" class="list-group-item list-group-item-action ps-5">{{ $childCategory->name }}</a>
                            @endforeach
                        </div>
                    @else
                        <a href="{{route('category.show', $category->slug)}}"
                           class="list-group-item list-group-item-action d-flex justify-content-between align-items-center">
                            <i class="bi bi-tag me-2"></i> {{ $category->name }} <i class="bi bi-chevron-right ms-auto"></i>
                        </a>
                    @endif
                @endforeach
            @endif
                    </div>
                </div>
                <!-- Menu Tab Content -->
                <div class="tab-pane fade" id="nav-menu" role="tabpanel" aria-labelledby="nav-menu-tab">
                    <div class="list-group list-group-flush">
                        <a href="{{route('home.index')}}" class="list-group-item list-group-item-action">Home</a>
                        <a href="#" class="list-group-item list-group-item-action">About Us</a>
                        <a href="#" class="list-group-item list-group-item-action">Contact</a>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- Offcanvas for Sign In Form -->
    @include('front.include.loginRegister')

    <!-- Offcanvas for Shopping Cart -->
    <div class="offcanvas offcanvas-end" tabindex="-1" id="cartOffcanvas" aria-labelledby="cartOffcanvasLabel">
        <div class="offcanvas-header">
            <h5 class="offcanvas-title" id="cartOffcanvasLabel">Shopping cart</h5>
            <button type="button" class="btn-close text-reset" data-bs-dismiss="offcanvas" aria-label="Close"></button>
        </div>
        <div class="offcanvas-body">
            <!-- Scrollable product list -->
            <div class="cart-products">
              <div class="text-center p-5">
                <div class="spinner-border" role="status">
                    <span class="visually-hidden">Loading...</span>
                </div>
            </div>
            </div>

            <!-- Fixed bottom section -->
            <div class="cart-fixed-bottom">
            <div class="d-flex justify-content-between align-items-center mb-3">
                <h5 class="mb-0" style="color:black;">Subtotal:</h5>
                <h5 class="mb-0 fw-bold" id="cart-subtotal" style="color:black;">৳ 0.00</h5>
            </div>
            <p class="text-muted small" id="cart-shipping-message">
                Shipping and taxes calculated at checkout.
            </p>
            <a href="{{route('cart.show')}}" class="btn btn-outline-dark">View Cart</a>
            @if (Auth::check())
            <a href="{{route('user.checkout')}}" class="btn btn-dark">Checkout</a>
            @else
             <a href="#" class="btn btn-dark" data-bs-toggle="offcanvas"
                        data-bs-target="#signInOffcanvas" aria-controls="signInOffcanvas">Checkout</a>
            @endif
        </div>
        </div>
    </div>

    <!-- Sticky Mobile Bottom Navigation -->
    <nav class="mobile-bottom-nav d-lg-none">
        <a href="{{ route('shop.show') }}" class="nav-link text-dark">
            <i class="bi bi-shop"></i>
            <span>Shop</span>
        </a>

       @if(Auth::check())
<a href="{{route('wishlist.index')}}" class="nav-link text-dark">
    <div class="position-relative">
        <i class="bi bi-heart"></i>
        <span id="mobile-wishlist-count" class="badge rounded-pill bg-danger">{{ Auth::user()->wishlist->count() }}</span>
    </div>
    <span>Wishlist</span>
</a>
@else
 <a href="#" class="nav-link text-dark" data-bs-toggle="offcanvas"
                data-bs-target="#signInOffcanvas" aria-controls="signInOffcanvas">
    <div class="position-relative">
        <i class="bi bi-heart"></i>
        <span id="mobile-wishlist-count" class="badge rounded-pill bg-danger">0</span>
    </div>
    <span>Wishlist</span>
</a>
@endif
        <a href="{{route('cart.show')}}" class="nav-link text-dark" data-bs-toggle="offcanvas" data-bs-target="#cartOffcanvas"
            aria-controls="cartOffcanvas">
            <div class="position-relative">
                <i class="bi bi-cart"></i>
                 <span id="mobile-cart-count" class="badge rounded-pill bg-dark">0</span>
            </div>
            <span>Cart</span>
        </a>
        <a href="{{route('shop.show')}}" class="nav-link text-dark" data-bs-toggle="offcanvas" data-bs-target="#mobileOffcanvas"
            aria-controls="mobileOffcanvas">
            <i class="bi bi-list"></i>
            <span>Menu</span>
        </a>
    </nav>