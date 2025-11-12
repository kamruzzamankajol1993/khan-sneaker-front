<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use App\Models\Product;
use Illuminate\Support\Facades\Session;
use Illuminate\Support\Facades\Validator;

class CompareController extends Controller
{
    /**
     * Display the product comparison page.
     */
    public function index()
    {
        $compare = Session::get('compare', []);
        $products = Product::whereIn('id', $compare)->with(['brand', 'category', 'variants'])->get();
        return view('front.compare.index', compact('products'));
    }

    /**
     * Add a product to the comparison list.
     */
    public function add(Request $request)
    {
        $request->validate(['product_id' => 'required|exists:products,id']);
        
        $productId = $request->product_id;
        $compare = Session::get('compare', []);

        // Limit the comparison to a maximum of 4 products
        if (count($compare) >= 4) {
            return response()->json(['success' => false, 'message' => 'You can only compare up to 4 products at a time.']);
        }

        if (!in_array($productId, $compare)) {
            Session::push('compare', $productId);
            $message = 'Product added to compare list!';
        } else {
            $message = 'This product is already in your compare list.';
        }
        
        return response()->json([
            'success' => true,
            'message' => $message,
            'count' => count(Session::get('compare', []))
        ]);
    }

    /**
     * Add multiple products (from a bundle) to the comparison list.
     */
    public function addMultiple(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'product_ids'   => 'required|array|min:1',
            'product_ids.*' => 'integer|exists:products,id',
        ]);

        if ($validator->fails()) {
            return response()->json(['success' => false, 'message' => 'Invalid product data.'], 422);
        }

        $productIds = $request->product_ids;
        $compare = Session::get('compare', []);
        
        $newCompareList = array_unique(array_merge($compare, $productIds));

        if (count($newCompareList) > 4) {
            return response()->json([
                'success' => false, 
                'message' => 'Cannot add these items. The compare list is limited to 4 products.'
            ]);
        }
        
        Session::put('compare', $newCompareList);

        return response()->json([
            'success' => true,
            'message' => 'Products added to compare list!',
            'count' => count($newCompareList)
        ]);
    }

    /**
     * Remove a product from the comparison list.
     */
    public function remove(Request $request)
    {
        $request->validate(['product_id' => 'required|exists:products,id']);

        $productId = $request->product_id;
        $compare = Session::get('compare', []);

        if (($key = array_search($productId, $compare)) !== false) {
            unset($compare[$key]);
            Session::put('compare', array_values($compare)); // Re-index the array
        }

        return response()->json([
            'success' => true,
            'message' => 'Product removed from compare list.',
            'count' => count(Session::get('compare', []))
        ]);
    }
    
    /**
     * Clear the entire comparison list.
     */
    public function clear()
    {
        Session::forget('compare');
        return redirect()->route('compare.index')->with('success', 'Compare list has been cleared.');
    }
}
