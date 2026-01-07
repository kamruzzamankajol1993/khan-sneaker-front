<?php

use Illuminate\Support\Facades\Route;
use App\Http\Controllers\FrontController;
use App\Http\Controllers\CartController;
use App\Http\Controllers\LocationController;
use App\Http\Controllers\AuthController;
use App\Http\Controllers\Admin\CheckoutController;
use App\Http\Controllers\WishlistController;
use App\Http\Controllers\ReviewController;
use App\Http\Controllers\CompareController;

Route::get('/clear', function() {
    \Illuminate\Support\Facades\Artisan::call('cache:clear');
    \Illuminate\Support\Facades\Artisan::call('config:clear');
    \Illuminate\Support\Facades\Artisan::call('config:cache');
    \Illuminate\Support\Facades\Artisan::call('view:clear');
    \Illuminate\Support\Facades\Artisan::call('route:clear');
    return redirect()->back();
});

Route::controller(CheckoutController::class)->group(function () {
   // --- ADDED: SSLCOMMERZ PAYMENT GATEWAY ROUTES ---
         Route::post('/pay', 'pay')->name('pay');
        Route::post('/ssl/success', 'sslSuccess')->name('sslcommerz.success');
        Route::post('/ssl/fail', 'sslFail')->name('sslcommerz.fail');
        Route::post('/ssl/cancel', 'sslCancel')->name('sslcommerz.cancel');
        Route::post('/ssl/ipn', 'sslIpn')->name('sslcommerz.ipn');

        // --- ADDED: BKASH PAYMENT GATEWAY ROUTES (PLACEHOLDER) ---
        Route::get('/bkash/success', 'bkashSuccess')->name('bkash.success');
        Route::get('/bkash/fail', 'bkashFail')->name('bkash.fail');

        // --- ADD THIS NEW ROUTE FOR BKASH ---
    Route::get('/bkash-callback', 'bkashCallback')->name('bkash.callback');
});
Route::get('/order-success/{orderId}', [CheckoutController::class, 'orderSuccess'])->name('order.success');
// --- Product Compare ---
Route::controller(CompareController::class)->prefix('compare')->name('compare.')->group(function () {
    Route::get('/', 'index')->name('index');
    Route::post('/add', 'add')->name('add');
    Route::post('/add-multiple', 'addMultiple')->name('addMultiple');
    Route::post('/remove', 'remove')->name('remove');
    Route::get('/clear', 'clear')->name('clear');
});

Route::middleware('auth')->group(function () {

     // --- Product Review Routes ---
    Route::controller(ReviewController::class)->prefix('reviews')->name('reviews.')->group(function () {
        Route::get('/', 'index')->name('index');
        Route::post('/store', 'store')->name('store');
    });

      Route::controller(WishlistController::class)->prefix('wishlist')->name('wishlist.')->group(function () {
        Route::get('/', 'index')->name('index');
        Route::post('/add', 'add')->name('add');
        Route::post('/add-bundle', 'addBundle')->name('addBundle');
        Route::post('/remove', 'remove')->name('remove');
        Route::post('/move-to-cart', 'moveToCart')->name('moveToCart');
    });

    Route::controller(CheckoutController::class)->group(function () {

        Route::get('/check-out-now', 'checkout')->name('user.checkout');
       
         // --- ADD THIS NEW ROUTE ---
        Route::post('/get-shipping-charge', 'getShippingCharge')->name('get.shipping.charge');

        Route::post('/place-order', 'placeOrder')->name('place.order');
        

      
    });

    Route::controller(AuthController::class)->group(function () {
 Route::get('/dashboard-user', 'dashboarduser')->name('dashboard.user');
  Route::post('/dashboard-picture-update', 'updateProfilePicture')->name('dashboard.picture.update');

Route::post('/user-order-cancel', 'cancelOrder')->name('user.order.cancel');
 Route::get('/user-order-invoice/{id}', 'downloadInvoice')->name('user.order.invoice');
  Route::post('/reorder', 'reorder')->name('user.reorder');
  // --- ADD THESE NEW ROUTES FOR PROFILE UPDATES ---
        Route::post('/dashboard/profile-info-update', 'updateProfileInfo')->name('dashboard.profile.info.update');
        Route::post('/dashboard/send-verification-otp', 'sendUpdateVerificationOtp')->name('dashboard.send.otp');
        Route::post('/dashboard/verify-and-update', 'verifyAndUpdateField')->name('dashboard.verify.update');
    // --- END NEW ROUTES ---
        Route::get('/user-order-list', 'userOrderList')->name('user.order.list');
        Route::get('/user-order-detail/{id}', 'userOrderDetail')->name('user.order.detail');
        Route::get('/user-address-update', 'updateProfileAddress')->name('dashboard.profile.address.update');

          // --- ADD THESE NEW ROUTES FOR ADDRESS MANAGEMENT ---
        Route::post('/dashboard/address/store', 'storeAddress')->name('dashboard.address.store');
        Route::post('/dashboard/address/update', 'updateAddress')->name('dashboard.address.update');
        Route::post('/dashboard/address/delete', 'destroyAddress')->name('dashboard.address.delete');
        Route::post('/dashboard/address/set-default', 'setDefaultAddress')->name('dashboard.address.setDefault');

    });
});
Route::get('/auth/google/redirect', [AuthController::class, 'redirectToGoogle'])->name('auth.google.redirect');
Route::get('/auth/google/callback', [AuthController::class, 'handleGoogleCallback'])->name('auth.google.callback');
// Authentication Routes
Route::post('/login', [AuthController::class, 'login'])->name('customer.login');
Route::post('/register', [AuthController::class, 'register'])->name('customer.register');
Route::post('/verify-otp', [AuthController::class, 'verifyOtp'])->name('customer.verifyOtp');
Route::post('/resend-otp', [AuthController::class, 'resendOtp'])->name('customer.resendOtp');
Route::post('/logout', [AuthController::class, 'logout'])->name('customer.logout');

// --- MODIFIED: Password Reset Routes (Phone OTP Based) ---
Route::post('/password/send-otp', [AuthController::class, 'sendPasswordResetOtp'])->name('password.sendOtp');
Route::post('/password/verify-otp', [AuthController::class, 'verifyPasswordResetOtp'])->name('password.verifyOtp');
Route::post('/password/update-new', [AuthController::class, 'updatePasswordFromOtp'])->name('password.updateNew');
Route::post('/password/resend-otp', [AuthController::class, 'resendPasswordResetOtp'])->name('password.resendOtp');
// --- END: Password Reset Routes ---

Route::post('/forgot-password', [AuthController::class, 'sendPasswordResetLink'])->name('password.email');
Route::get('/reset-password/{token}', [AuthController::class, 'showResetForm'])->name('password.reset');
Route::post('/reset-password', [AuthController::class, 'resetPassword'])->name('password.update');



Route::get('/locations-districts', [LocationController::class, 'getDistricts'])->name('locations.districts');
Route::get('/locations-upazilas', [LocationController::class, 'getUpazilas'])->name('locations.upazilas');
Route::controller(FrontController::class)->group(function () {
    Route::get('/bundle-view-count/{id}', [FrontController::class, 'getBundleViewCount'])->name('bundle.view_count');
Route::get('/product-view-count/{id}', 'getProductViewCount')->name('product.view_count');
     Route::get('/products/ajax-search-filter', 'ajaxSearchFilter')->name('products.ajax_search_filter');

    Route::get('/products/ajax-search', 'ajaxSearch')->name('products.ajax_search');
    Route::get('/product-search', 'productSearch')->name('products.search');

    Route::get('/', 'index')->name('home.index');
Route::get('/offers', 'offers')->name('offers');
      Route::get('/discount-filter', 'ajaxDiscountFilter')->name('discount.ajax_filter');

    Route::get('/category/{slug}', 'category')->name('category.show');
    Route::get('/extra-category/{slug}', 'extra_category_offer')->name('extra_category_offer.show');
    Route::get('/extra_category/{slug}', 'extra_category')->name('extra_category.show');
    Route::get('/subcategory/{slug}', 'subcategory')->name('subcategory.show');
    // ADD THESE NEW ROUTES FOR THE OFFER PAGE
    Route::get('/offer/{slug}','offer')->name('offer.show');
    Route::get('/offer-product/{id}','offerProduct')->name('offerProduct.show');
    Route::get('/offers/filter','filterOffers')->name('offer.filter');

    Route::get('/animation-category/{slug}', 'animationCategory')->name('animation.category.show');
    Route::get('/animation-category-filter', 'filterAnimationCategory')->name('animation.category.filter');

    Route::get('/shop', 'shop')->name('shop.show');
    Route::get('/product/{slug}', 'product')->name('product.show');
    Route::get('/shop-filter', 'ajaxShopFilter')->name('shop.ajax_filter');
    Route::get('products-filter', 'filterProducts')->name('products.filter');
     Route::get('/product-quick-view/{id}', 'quickView')->name('product.quick_view');

});

// START: MODIFIED CART ROUTES

Route::controller(CartController::class)->prefix('cart')->name('cart.')->group(function () {

    Route::post('/cart-add-bundle', [CartController::class, 'addBundleToCart'])->name('addBundle');
 // --- ADD THESE NEW ROUTES FOR COUPONS ---
    Route::post('/apply-coupon', 'applyCoupon')->name('applyCoupon');
    Route::post('/remove-coupon', 'removeCoupon')->name('removeCoupon');

    Route::get('/showCartData', 'showCartData')->name('show');
    Route::post('/add', 'addToCart')->name('add');
    Route::get('/content', 'getCartContent')->name('content');
     Route::get('/main-content', 'getMainCartContent')->name('main_content');
    Route::post('/main-update', 'updateMainCartItem')->name('main.update');
    Route::post('/main-remove', 'removeMainCartItem')->name('main.remove');
    Route::post('/update', 'updateCartItem')->name('update');
    Route::post('/remove', 'removeCartItem')->name('remove');
});
// END: MODIFIED CART ROUTES
