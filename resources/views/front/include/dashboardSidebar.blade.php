<div class="spotlight_user_profile_sidebar">
                                    <div class="spotlight_user_profile_sidebar-header">
                                         <div class="spotlight_user_profile_user-avatar-container" id="sidebar-avatar-container" @if(Auth::user()->image) style="background: transparent;" @endif>
                                    @if(Auth::user()->image)
                                        <img src="{{ asset('public/'.Auth::user()->image) }}" alt="User Avatar" style="height: 40px !important;" class="spotlight_user_profile_user-avatar">
                                    @else
                                        <i class="bi bi-person-fill"></i>
                                    @endif
                                </div>
                                        <div class="spotlight_user_profile_user-info">
                                            <div class="spotlight_user_profile_user-name">{{ Auth::user()->name }}</div>
                                           
                                            <a href="{{route('dashboard.user')}}" class="spotlight_user_profile_view-profile-link">View
                                                Profile</a>
                                        </div>
                                    </div>
                                    <ul class="list-group list-group-flush spotlight_user_profile_nav-list">
                                        <li class="list-group-item {{ Route::is('dashboard.user') ? 'active' : '' }}"><a href="{{ route('dashboard.user') }}" class="text-decoration-none text-dark"><i class="bi bi-person-fill"></i> View Profile</a></li>
                                <li class="list-group-item d-flex justify-content-between align-items-center"
                                    data-bs-toggle="collapse" href="#orders-collapse" role="button"
                                    aria-expanded="false" aria-controls="orders-collapse">
                                    <span><a href="#" class="text-decoration-none text-dark"><i
                                                class="bi bi-cart-fill"></i> Orders</a></span>
                                    <i class="bi bi-chevron-right"></i>
                                </li>
                                <div class="collapse {{ Route::is('user.order.list') || Route::is('user.order.detail') || Route::is('reviews.index') ? 'show' : '' }}" id="orders-collapse">
                                    <ul class="list-group list-group-flush ms-4">
                                        <li class="list-group-item {{ Route::is('user.order.list') || Route::is('user.order.detail')  ? 'active' : '' }}"><a href="{{route('user.order.list')}}"
                                                class="text-decoration-none text-dark"><i
                                                    class="bi bi-check-circle-fill text-success"></i> My
                                                Orders</a></li>
                                        <li class="list-group-item {{ Route::is('reviews.index') ? 'active' : '' }}">
                    <a href="{{ route('reviews.index') }}" class="text-decoration-none text-dark">
                        <i class="bi bi-star-fill text-muted"></i> Product Review
                    </a>
                </li>
                                    </ul>
                                </div>
                                        <li class="list-group-item {{ Route::is('wishlist.index') ? 'active' : '' }}"><a href="{{route('wishlist.index')}}"
                                                class="text-decoration-none text-dark"><i class="bi bi-heart-fill"></i>
                                                Wishlist</a></li>
                                        <li class="list-group-item {{ Route::is('dashboard.profile.address.update') ? 'active' : '' }}"><a href="{{route('dashboard.profile.address.update')}}"
                                                class="text-decoration-none text-dark"><i
                                                    class="bi bi-pin-map-fill"></i> Manage Address</a></li>
                                        <li class="list-group-item">
                                    <a href="#" class="text-decoration-none text-dark" onclick="event.preventDefault(); document.getElementById('logout-form').submit();">
                                        <i class="bi bi-door-open-fill"></i> Logout
                                    </a>
                                    <form id="logout-form" action="{{ route('customer.logout') }}" method="POST" style="display: none;">
                                        @csrf
                                    </form>
                                </li>

                                    </ul>
                                </div>