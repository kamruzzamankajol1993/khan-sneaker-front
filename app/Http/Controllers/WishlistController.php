<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Validator;
use App\Models\Wishlist;
use App\Models\Product;
use App\Models\ProductVariant;
use Session;
class WishlistController extends Controller
{

     public function index()
    {
        $user = Auth::user();
        $customer = $user->customer;

        // Eager load the product and variant relationships for efficiency
        $wishlistItems = Wishlist::where('user_id', $user->id)
                                ->with(['product', 'productVariant.color'])
                                ->latest()
                                ->get();
        
        return view('front.dashboard.user_wishlist', [
            'user' => $customer,
            'wishlistItems' => $wishlistItems
        ]);
    }
    /**
     * Add a product to the user's wishlist.
     */
    public function add(Request $request)
    {
        // Users must be logged in to add to wishlist
        if (!Auth::check()) {
            return response()->json(['success' => false, 'message' => 'Please log in to add items to your wishlist.', 'action' => 'login'], 401);
        }

        $validator = Validator::make($request->all(), [
            'product_id' => 'required|exists:products,id',
            'variant_id' => 'required|exists:product_variants,id',
            'size'       => 'required|string',
        ]);

        if ($validator->fails()) {
            return response()->json(['success' => false, 'message' => $validator->errors()->first()], 422);
        }

        // Check if the item already exists in the wishlist
        $exists = Wishlist::where('user_id', Auth::id())
                          ->where('product_variant_id', $request->variant_id)
                          ->where('size', $request->size)
                          ->first();

        if ($exists) {
            return response()->json(['success' => false, 'message' => 'This item is already in your wishlist.']);
        }

        // Add the item to the wishlist
        Wishlist::create([
            'user_id'            => Auth::id(),
            'product_id'         => $request->product_id,
            'product_variant_id' => $request->variant_id,
            'size'               => $request->size,
        ]);

        $count = Auth::user()->wishlist()->count();

return response()->json([
    'success' => true, 
    'message' => 'Product added to your wishlist!',
    'count' => $count
]);
    }

    public function addBundle(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'selected_products' => 'required|array|min:1',
            'selected_products.*.id' => 'required|exists:products,id',
            'selected_products.*.variantId' => 'required|exists:product_variants,id',
            'selected_products.*.size' => 'required|string',
        ]);

        if ($validator->fails()) {
            return response()->json(['success' => false, 'message' => 'Invalid product data provided.'], 422);
        }

        $user_id = Auth::id();
        $itemsAdded = 0;
        $itemsAlreadyExist = 0;

        foreach ($request->selected_products as $product) {
            $wishlistItem = Wishlist::firstOrCreate(
                [
                    'user_id'            => $user_id,
                    'product_variant_id' => $product['variantId'],
                    'size'               => $product['size'],
                ],
                [
                    'product_id'         => $product['id'],
                ]
            );

            if ($wishlistItem->wasRecentlyCreated) {
                $itemsAdded++;
            } else {
                $itemsAlreadyExist++;
            }
        }
        
        $message = '';
if ($itemsAdded > 0) {
    $message .= "$itemsAdded item(s) added to your wishlist. ";
}
if ($itemsAlreadyExist > 0) {
    $message .= "$itemsAlreadyExist item(s) were already in your wishlist.";
}

// Get the new total count of items in the wishlist
$count = Auth::user()->wishlist()->count();

return response()->json([
    'success' => true, 
    'message' => trim($message),
    'count' => $count // Return the new count
]);
    }

    public function remove(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'wishlist_id' => 'required|exists:wishlists,id',
        ]);
        if ($validator->fails()) {
            return response()->json(['success' => false, 'message' => 'Invalid item.'], 422);
        }

        $wishlistItem = Wishlist::where('id', $request->wishlist_id)
                                ->where('user_id', Auth::id())
                                ->first();

        if ($wishlistItem) {
    $wishlistItem->delete();
    $count = Auth::user()->wishlist()->count();

    return response()->json([
        'success' => true, 
        'message' => 'Item removed from wishlist.',
        'count' => $count
    ]);
}

        return response()->json(['success' => false, 'message' => 'Item not found in your wishlist.'], 404);
    }

    /**
     * Move a wishlist item to the shopping cart.
     * This will always add the item as a single product, not a bundle.
     */
    public function moveToCart(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'wishlist_id' => 'required|exists:wishlists,id',
        ]);
        if ($validator->fails()) {
            return response()->json(['success' => false, 'message' => 'Invalid item.'], 422);
        }

        $wishlistItem = Wishlist::where('id', $request->wishlist_id)
                               ->where('user_id', Auth::id())
                               ->first();

        if (!$wishlistItem) {
            return response()->json(['success' => false, 'message' => 'Item not found.'], 404);
        }

        $product = Product::find($wishlistItem->product_id);
        $variant = ProductVariant::with('color')->find($wishlistItem->product_variant_id);

        if (!$product || !$variant) {
            $wishlistItem->delete(); // Clean up wishlist if product is unavailable
            return response()->json(['success' => false, 'message' => 'This product is no longer available and has been removed from your wishlist.'], 404);
        }

        $cartItemId = $variant->id . '-' . str_replace(' ', '', $wishlistItem->size);
        $cart = Session::get('cart', []);
        
        $basePrice = $product->discount_price ?? $product->base_price;
        $finalPrice = $basePrice + ($variant->additional_price ?? 0);
        $image = $variant->variant_image[0] ?? $product->thumbnail_image[0] ?? null;

        if (isset($cart[$cartItemId])) {
            $cart[$cartItemId]['quantity']++;
        } else {
            $cart[$cartItemId] = [
                'rowId' => $cartItemId, 'product_id' => $product->id, 'variant_id' => $variant->id, 'name' => $product->name,
                'size' => $wishlistItem->size, 'color' => $variant->color->name ?? 'N/A', 'quantity' => 1,
                'price' => $finalPrice, 'image' => $image, 'slug' => $product->slug, 'is_bundle' => false,
                'url' => route('product.show', $product->slug)
            ];
        }

        Session::put('cart', $cart);
        $wishlistItem->delete(); // Remove from wishlist after adding to cart
$count = Auth::user()->wishlist()->count();

return response()->json([
    'success' => true, 
    'message' => 'Item moved to cart!',
    'count' => $count
]);
    }

}
