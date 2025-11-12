<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Validator;
use Illuminate\Support\Facades\DB;
use App\Models\ProductReview;
use App\Models\ProductReviewImage;
use App\Models\Order;
use Exception;

class ReviewController extends Controller
{
    /**
     * Display the page with all purchased products eligible for review.
     */
    public function index()
    {
        $user = Auth::user();
        $customer = $user->customer;

        // Get all unique product IDs from the user's delivered orders
        $purchasedProductIds = Order::where('customer_id', $customer->id)
            ->where('status', 'Delivered')
            ->with('orderDetails')
            ->get()
            ->pluck('orderDetails.*.product_id')
            ->flatten()
            ->unique();
            
        // Get the products the user has already reviewed
        $reviewedProductIds = ProductReview::where('user_id', $user->id)->pluck('product_id');

        // Get the products that are purchased but not yet reviewed
        $productsToReview = \App\Models\Product::whereIn('id', $purchasedProductIds)
            ->whereNotIn('id', $reviewedProductIds)
            ->with('category')
            ->paginate(10);

        return view('front.dashboard.user_product_review', [
            'user' => $customer,
            'productsToReview' => $productsToReview
        ]);
    }

    /**
     * Store a new product review.
     */
    public function store(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'product_id' => 'required|exists:products,id',
            'rating'     => 'required|integer|min:1|max:5',
            'description'=> 'nullable|string|max:1000',
            'images.*'   => 'nullable|image|mimes:jpeg,png,jpg,gif|max:2048' // Validate each image
        ]);

        if ($validator->fails()) {
            return response()->json(['success' => false, 'message' => $validator->errors()->first()], 422);
        }

        $user = Auth::user();
        
        // Final check to ensure the user has actually purchased this product
        $hasPurchased = Order::where('customer_id', $user->customer->id)
                            ->where('status', 'Delivered')
                            ->whereHas('orderDetails', fn($q) => $q->where('product_id', $request->product_id))
                            ->exists();

        if (!$hasPurchased) {
            return response()->json(['success' => false, 'message' => 'You can only review products you have purchased.'], 403);
        }

        try {
            DB::beginTransaction();
            
            $review = ProductReview::create([
                'user_id'     => $user->id,
                'product_id'  => $request->product_id,
                'rating'      => $request->rating,
                'description' => $request->description,
            ]);

            if ($request->hasFile('images')) {
                foreach ($request->file('images') as $image) {
                    $imageName = 'review-' . $review->id . '-' . uniqid() . '.' . $image->extension();
                    $image->move(public_path('uploads/review_images'), $imageName);
                    
                    ProductReviewImage::create([
                        'product_review_id' => $review->id,
                        'image_path'        => 'uploads/review_images/' . $imageName,
                    ]);
                }
            }

            DB::commit();
            return response()->json(['success' => true, 'message' => 'Thank you! Your review has been submitted.']);

        } catch (Exception $e) {
            DB::rollBack();
            \Log::error('Review submission failed: ' . $e->getMessage());
            return response()->json(['success' => false, 'message' => 'Could not submit review. Please try again.'], 500);
        }
    }
}
