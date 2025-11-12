<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cookie;
use App\Models\Product;
use App\Models\AnimationCategory;
use App\Models\BundleOfferProduct;
use App\Models\SliderControl;
use Illuminate\Support\Facades\DB;
use App\Models\Category;
use App\Models\Subcategory;
use App\Models\HighlightProduct;
use App\Models\AssignCategory;
use App\Models\FeaturedCategory;
use App\Models\BundleOffer;
use App\Models\Size;
use App\Models\HomepageSection; 
use App\Models\HeroLeftSlider;
use App\Models\HeroRightSlider;
use App\Models\FooterBanner;
use App\Models\ExtraCategory;
use App\Models\AreaWisePrice; 
class FrontController extends Controller
{


    private function applyFilters(\Illuminate\Http\Request $request, $query)
{

    // NEW: Handle the search query filter
    if ($request->filled('query')) {
        $query->where('name', 'LIKE', '%' . $request->input('query') . '%');
    }
    // Filter by Category, Subcategory, or Animation Category
    $categoryId = $request->input('category_id') ?: $request->input('subcategory_id');
    if ($categoryId) {
        $productIds = \App\Models\AssignCategory::where('category_id', $categoryId)->where('type', 'product_category')->pluck('product_id');
        $query->whereIn('id', $productIds);
    }
    if ($request->filled('animation_category_id')) {
        $productIds = \App\Models\AssignCategory::where('category_id', $request->animation_category_id)->where('type', 'animation')->pluck('product_id');
        $query->whereIn('id', $productIds);
    }

    // Filter by Price Range
    if ($request->filled('min_price') && $request->min_price > 0) {
        $query->where('base_price', '>=', (float)$request->min_price);
    }
    if ($request->filled('max_price') && $request->max_price < 10000) {
        $query->where('base_price', '<=', (float)$request->max_price);
    }

    // Filter by Stock Status
    if ($request->filled('stock_status')) {
        if ($request->stock_status === 'offer') {
            $query->whereNotNull('discount_price')->where('discount_price', '>', 0);
        } elseif ($request->stock_status === 'in_stock') {
            $query->whereHas('variants', fn($q) => $q->whereJsonLength('sizes', '>', 0));
        }
    }

    // Filter by Size
    if ($request->filled('sizes') && is_array($request->sizes)) {
        $selectedSizeNames = $request->sizes;
        $sizeIds = \App\Models\Size::whereIn('name', $selectedSizeNames)->pluck('id')->toArray();
        if (!empty($sizeIds)) {
            $query->whereHas('variants', function ($variantQuery) use ($sizeIds) {
                $variantQuery->where(function ($q) use ($sizeIds) {
                    foreach ($sizeIds as $sizeId) {
                        $q->orWhereJsonContains('sizes', ['size_id' => (string)$sizeId]);
                    }
                });
            });
        }
    }

    // Sorting Logic
    $sortBy = $request->input('sort_by', 'newest');
    switch ($sortBy) {
        case 'price_asc':
            $query->orderByRaw('ISNULL(discount_price), discount_price ASC, base_price ASC');
            break;
        case 'price_desc':
            $query->orderByRaw('ISNULL(discount_price), discount_price DESC, base_price DESC');
            break;
        case 'name_asc':
            $query->orderBy('name', 'asc');
            break;
        case 'popularity':
        case 'newest':
        default:
            $query->latest();
            break;
    }

    return $query;
}


      /**
     * Handle AJAX search requests for products.
     */
    public function ajaxSearch(Request $request)
    {
        $query = $request->input('query');

        if (!$query || strlen($query) < 1) {
            return response()->json([]);
        }


        $frontEndData = DB::table('system_information')->first();

        

        $products = Product::where('status', 1)
        
            ->with(['category', 'variants', 'productCategoryAssignment.category']) ->withCount('reviews')
    ->withAvg('reviews', 'rating')
                           ->where('name', 'LIKE', "%{$query}%")
                           ->select('name', 'slug', 'main_image', 'base_price', 'discount_price')
                           ->take(10) // Limit the number of results
                           ->get();

        // Prepare the data for the frontend, including image and product URLs
        $products->transform(function ($product) use ($frontEndData) {
            $imageUrl = (is_array($product->main_image) && count($product->main_image) > 0)
                ? $frontEndData->main_url . 'public/uploads/' . $product->main_image[0]
                : 'https://placehold.co/50x50?text=N/A';
            
            $product->image_url = $imageUrl;
            $product->url = route('product.show', $product->slug);
            return $product;
        });

        return response()->json($products);
    }


    public function offerProduct($id)
    {
        $bundleDeal = BundleOfferProduct::findOrFail($id);
         $bundleDeal->increment('view_count');
        $productIds = $bundleDeal->product_id;
        $productsCollection = collect();
        $allImages = [];
        $totalBasePrice = 0;

        if (!empty($productIds) && is_array($productIds)) {
            $productsCollection = Product::whereIn('id', $productIds)
                ->with([
                    'variants.color', 
                    'productCategoryAssignment.category',
                    'reviews.user',
                    'reviews.images'
                ])
                ->withCount('reviews')
                ->withAvg('reviews', 'rating')
                ->get();

            // Collect images from all available products for the gallery
            foreach ($productsCollection as $product) {
                if (is_array($product->main_image) && count($product->main_image) > 0) {
                    $allImages = array_merge($allImages, $product->main_image);
                }
            }

            // --- START: CORRECTED PRICE CALCULATION ---
            // Key products by ID for efficient lookup.
            $productsKeyedById = $productsCollection->keyBy('id');

            // Determine how many products to sum based on 'buy_quantity'.
            $quantityToConsider = (isset($bundleDeal->buy_quantity) && $bundleDeal->buy_quantity > 0)
                                  ? (int)$bundleDeal->buy_quantity
                                  : count($bundleDeal->product_id);
            
            // Get the specific number of product IDs from the start of the array.
            $productIdsToSum = array_slice($bundleDeal->product_id, 0, $quantityToConsider);

            // Calculate the total base price for only those products.
            foreach ($productIdsToSum as $pid) {
                if (isset($productsKeyedById[$pid])) {
                    $totalBasePrice += $productsKeyedById[$pid]->base_price;
                }
            }
            // --- END: CORRECTED PRICE CALCULATION ---
        }

        $allImages = array_unique($allImages);
$areaWisePrice = AreaWisePrice::all();
        return view('front.offer.offerproduct', compact(
            'bundleDeal',
            'productsCollection',
            'allImages',
            'totalBasePrice',
            'areaWisePrice'
        ));
    }
public function getBundleViewCount($id)
{
    $bundle = BundleOfferProduct::find($id, ['view_count']);
    
    if ($bundle) {
        return response()->json(['success' => true, 'view_count' => $bundle->view_count]);
    }

    return response()->json(['success' => false, 'message' => 'Bundle not found'], 404);
}
   public function quickView($id)
{
    // 1. Fetch the product without the old 'category' relationship
    $product = Product::with(['variants.color', 'productCategoryAssignment.category'])
        ->findOrFail($id);
    
    // 2. Find the category assignment from the pivot table
    $assignedCategory = AssignCategory::where('product_id', $product->id)->first();
    
    // 3. If an assignment exists, load the full Category model
    if ($assignedCategory) {
        $category = Category::find($assignedCategory->category_id);
        if ($category) {
            // Manually set the 'category' relation on the product object
            // This allows the view to still use `$product->category`
            $product->setRelation('category', $category);
        }
    }
    
    return view('front.include.quick_view_modal_content', compact('product'));
}

     public function product(Request $request,$slug)
{
    // 1. Fetch the product, removing 'category' and 'subcategory' from the with() array.
    $product = Product::where('slug', $slug)
        ->with([
            'variants.color'
            , 'productCategoryAssignment.category',
            'assignChart.entries',
            'reviews.user',
            'reviews.images'
        ])
        ->withCount('reviews')
        ->withAvg('reviews', 'rating')
        ->firstOrFail();
$product->increment('view_count');

// --- START: VIEW TRACKING LOGIC ---
    $viewed = json_decode($request->cookie('recently_viewed', '[]'), true);
    // Remove the current product ID if it already exists to avoid duplicates
    $viewed = array_diff($viewed, [$product->id]);
    // Add the current product ID to the beginning of the array
    array_unshift($viewed, $product->id);
    // Keep only the last 10 viewed products
    $viewed = array_slice($viewed, 0, 10);
    // Create a cookie that lasts for 30 days
    $cookie = Cookie::make('recently_viewed', json_encode($viewed), 60 * 24 * 30);
    // --- END: VIEW TRACKING LOGIC ---
    // 2. Get all category IDs assigned to this product from the pivot table.
    $assignedCategoryIds = AssignCategory::where('product_id', $product->id)->pluck('category_id');

    if ($assignedCategoryIds->isNotEmpty()) {
        // 3. Fetch the actual Category models for all assignments, eager-loading their parents.
        $assignedCategories = Category::whereIn('id', $assignedCategoryIds)->with('parent')->get();

        // 4. Find the most specific category (the one with a parent) to use as the "subcategory".
        $subcategory = $assignedCategories->firstWhere('parent_id', '!=', null);

        // 5. Determine the parent "category".
        // If a subcategory was found, its parent is the main category.
        // Otherwise, fall back to the first assigned category.
        $category = $subcategory ? $subcategory->parent : $assignedCategories->first();
        
        // 6. Manually set the relations on the product object.
        // This allows your view to use `$product->category` and `$product->subcategory` without any changes.
        if ($category) {
            $product->setRelation('category', $category);
        }
        if ($subcategory) {
            $product->setRelation('subcategory', $subcategory);
        }
    }

    $areaWisePrice = AreaWisePrice::all();

    return view('front.product.show', compact('product', 'areaWisePrice'));
}
public function getProductViewCount($id)
{
    $product = Product::find($id, ['view_count']);
    
    if ($product) {
        return response()->json(['success' => true, 'view_count' => $product->view_count]);
    }

    return response()->json(['success' => false, 'message' => 'Product not found'], 404);
}
    public function offers()
{
    // Find the 'discount' category details to pass to the view for context
    $extraCategory = ExtraCategory::where('slug', 'discount')->firstOrFail();

    // The rest of the function remains the same...
    $getAllid = AssignCategory::where('category_name', 'discount')->pluck('product_id');

    $products = Product::where('status', 1)
        ->whereIn('id', $getAllid)
        ->with(['category', 'variants', 'productCategoryAssignment.category']) ->withCount('reviews')
    ->withAvg('reviews', 'rating')
        ->latest()
        ->paginate(12);

    $productIdsOnPage = $products->pluck('id');
    if ($productIdsOnPage->isNotEmpty()) {
        $assignments = AssignCategory::whereIn('product_id', $productIdsOnPage)->get()->keyBy('product_id');
        $categoryIds = $assignments->pluck('category_id')->unique();
        $categories = Category::whereIn('id', $categoryIds)->get()->keyBy('id');

        foreach ($products as $product) {
            $assignment = $assignments->get($product->id);
            if ($assignment) {
                $category = $categories->get($assignment->category_id);
                $product->setRelation('category', $category);
            }
        }
    }
        
    $sizes = Size::where('status', 1)->get();

    // Pass the new $extraCategory variable to the view
    return view('front.discount.list', compact('products', 'sizes', 'extraCategory'));
}


public function extra_category_offer(Request $request, $slug)
{
    // 1. Find the details of the extra category itself.
    $extraCategory = ExtraCategory::where('slug', $slug)->firstOrFail();

    // 2. Get all product IDs assigned to this extra category.
    $productIds = AssignCategory::where('category_name', $slug)->pluck('product_id');

    // 3. Create the base query for these products.
    $query = Product::whereIn('id', $productIds)->where('status', 1);

    // 4. IMPORTANT: Apply all additional filters from the URL.
    $query = $this->applyFilters($request, $query);

    // 5. Paginate the final, filtered results.
    $products = $query->with(['variants', 'productCategoryAssignment.category'])
        ->withCount('reviews')
        ->withAvg('reviews', 'rating')
        ->paginate(12);
        
    // 6. Fetch available sizes for the filter sidebar.
    $sizes = Size::where('status', 1)->get();

    return view('front.discount.list', compact('products', 'sizes', 'extraCategory'));
}

public function ajaxDiscountFilter(Request $request)
{
    // Get the category slug from the request.
    $slug = $request->input('extra_category_slug');

    // 1. Get the base product IDs for this extra category.
    $productIds = AssignCategory::where('category_name', $slug)->pluck('product_id');
    
    // 2. Start the query from the correct set of products.
    $query = Product::whereIn('id', $productIds)->where('status', 1);
    
    // 3. Use the central helper to apply all other filters.
    $query = $this->applyFilters($request, $query);

    $products = $query->with(['variants', 'productCategoryAssignment.category'])
        ->withCount('reviews')
        ->withAvg('reviews', 'rating')
        ->paginate(12);

    // Manually load categories for the current page of products
    // ... (your existing manual category loading logic can remain here) ...

    $html = view('front.category.product_card_partial', compact('products'))->render();

    return response()->json([
        'html' => $html,
        'hasMorePages' => $products->hasMorePages(),
    ]);
}

     public function index()
{
    // --- START: NEW HERO SECTION LOGIC ---
    // Fetch active left sliders, ordered by latest, with their linked item (product, category, etc.)
    $heroLeftSliders = HeroLeftSlider::where('status', 1)->with('linkable')->latest()->get();

    // Fetch all active right sliders/banners with their linked items
    $allRightSliders = HeroRightSlider::where('status', 1)->with('linkable')->get();

    // Separate the right-side banners by their designated position
    $heroTopBanner = $allRightSliders->where('position', 'top')->first();
    // Assuming bottom banner positions are 'bottom_1' and 'bottom_2'
    $heroBottomBanners = $allRightSliders->whereIn('position', ['bottom_left', 'bottom_right'])->take(2);
    // --- END: NEW HERO SECTION LOGIC ---

    // Fetch Featured Category (Trending/New/Discount) sections
    $featuredCategorySettings = FeaturedCategory::pluck('value', 'key')->all();
    $titles = ExtraCategory::where('status', 1)->pluck('name', 'slug');
    
    $topProductsType = $featuredCategorySettings['first_row_category'] ?? null;
    $topProductsStatus = $featuredCategorySettings['first_row_status'] ?? false;
    $products = collect();
    $topRatedTitle = '';
    if ($topProductsStatus && $topProductsType) {
        $topRatedTitle = $titles[$topProductsType] ?? 'Top Rated Products';
        $productIds = AssignCategory::where('category_name', $topProductsType)->pluck('product_id');
        if ($productIds->isNotEmpty()) {
            $products = Product::whereIn('id', $productIds)->where('status', 1)
            ->with(['category', 'variants','assigns', 'productCategoryAssignment.category']) 
            ->withCount('reviews')
    ->withAvg('reviews', 'rating')->latest()->take(8)->get();
        }
    }
    
    $secondRowType = $featuredCategorySettings['second_row_category'] ?? null;
    $secondRowStatus = $featuredCategorySettings['second_row_status'] ?? false;
    $secondRowProducts = collect();
    $secondRowTitle = '';
    if ($secondRowStatus && $secondRowType) {
        $secondRowTitle = $titles[$secondRowType] ?? 'More For You';
        $productIds = AssignCategory::where('category_name', $secondRowType)->pluck('product_id');
        if ($productIds->isNotEmpty()) {
            $secondRowProducts = Product::whereIn('id', $productIds)->where('status', 1)->with(['category', 'variants','assigns', 'productCategoryAssignment.category']) ->withCount('reviews')
    ->withAvg('reviews', 'rating')->latest()->take(8)->get();
        }
    }

    // Fetch Homepage Section (Category-based) data
    // Fetch Homepage Section (Category-based) data
$homepageRow1 = HomepageSection::with('category')->where('row_identifier', 'row_1')->where('status', 1)->first();
$homepageRow2 = HomepageSection::with('category')->where('row_identifier', 'row_2')->where('status', 1)->first();

$row1Products = collect();
if ($homepageRow1 && $homepageRow1->category) {
    // Get product IDs from the assignment table for the first row's category
    $productIds = AssignCategory::where('category_id', $homepageRow1->category_id)->where('type','product_category')->pluck('product_id');
    $row1Products = Product::whereIn('id', $productIds)
        ->where('status', 1)
        ->with('variants','assigns', 'productCategoryAssignment.category')
         ->withCount('reviews')
    ->withAvg('reviews', 'rating')
        ->latest()
        ->take(8)
        ->get();
}

$row2Products = collect();
if ($homepageRow2 && $homepageRow2->category) {
    // Get product IDs from the assignment table for the second row's category
    $productIds = AssignCategory::where('category_id', $homepageRow2->category_id)->where('type','product_category')->pluck('product_id');
    $row2Products = Product::whereIn('id', $productIds)
        ->where('status', 1)
        ->with('variants','assigns', 'productCategoryAssignment.category')
         ->withCount('reviews')
    ->withAvg('reviews', 'rating')
        ->latest()
        ->take(8)
        ->get();
}

// Manually load categories for all fetched homepage products for efficiency
$allHomepageProducts = $row1Products->merge($row2Products);
$productIdsOnPage = $allHomepageProducts->pluck('id')->unique();

if ($productIdsOnPage->isNotEmpty()) {
    $assignments = AssignCategory::whereIn('product_id', $productIdsOnPage)->get()->keyBy('product_id');
    $categoryIds = $assignments->pluck('category_id')->unique();
    $categories = Category::whereIn('id', $categoryIds)->get()->keyBy('id');

    // This loop attaches the correct category to each product object,
    // which updates the products within both $row1Products and $row2Products collections.
    foreach ($allHomepageProducts as $product) {
        $assignment = $assignments->get($product->id);
        if ($assignment) {
            $category = $categories->get($assignment->category_id);
            if ($category) {
                // This ensures your view can still use `$product->category`
                $product->setRelation('category', $category);
            }
        }
    }
}
// --- END: UPDATED HOMEPAGE SECTION LOGIC ---

    // Fetch other necessary data for the homepage
    $featuredCategories = AnimationCategory::where('status', 1)->take(5)->get();
    $offerDeals = BundleOfferProduct::where('bundle_offer_id', 1)->get();
    $allProductIds = $offerDeals->pluck('product_id')->flatten()->unique()->all();
    $productsbun = Product::whereIn('id', $allProductIds)->get()->keyBy('id');
$footerBanner = FooterBanner::latest()->first();
    // Pass all data, including the new hero variables, to the view
    return view('front.index', compact(
        'productsbun', 'offerDeals', 'featuredCategories',
        'products', 'topRatedTitle', 'secondRowProducts', 'secondRowTitle',
        'homepageRow1', 'row1Products', 'homepageRow2', 'row2Products','footerBanner',
        'heroLeftSliders', 'heroTopBanner', 'heroBottomBanners' // <-- New variables for the hero section
    ));
}


    
public function category(Request $request, $slug)
{
    $category = Category::where('slug', $slug)->firstOrFail();

    // 1. Get all product IDs for the base category.
    $productIds = AssignCategory::where('category_id', $category->id)->where('type','product_category')->pluck('product_id');

    // 2. Create the initial query for products in this category.
    $query = Product::whereIn('id', $productIds)->where('status', 1);

    // 3. IMPORTANT: Apply all filters from the URL (price, sort, size, etc.).
    $query = $this->applyFilters($request, $query);

    // 4. Paginate the final, filtered results.
    $products = $query->with(['variants', 'productCategoryAssignment.category'])
        ->withCount('reviews')
        ->withAvg('reviews', 'rating')
        ->paginate(12);

    // The rest of the function remains the same.
    $categoryList = Category::where('status', 1)->whereNull('parent_id')->with('children')->get();
    $sizes = Size::where('status', 1)->get();

    return view('front.category.category', compact('category', 'products', 'categoryList', 'sizes'));
}
    public function productSearch(Request $request)
{
    $searchQuery = $request->input('query');

    if (!$searchQuery) {
        return redirect()->route('shop.show');
    }
    
    // Start a base query for active products
    $query = Product::where('status', 1);

    // Apply all filters from the request, including the search query
    $query = $this->applyFilters($request, $query);

    // Paginate the final, fully-filtered results
    $products = $query->with(['variants', 'productCategoryAssignment.category'])
        ->withCount('reviews')
        ->withAvg('reviews', 'rating')
        ->paginate(16);

    // Manually load categories for the current page of products
    // ... (your existing manual category loading logic can remain here if needed) ...

    // Fetch data for the filter sidebar
    $categoryList = Category::where('status', 1)->whereNull('parent_id')->with('children')->get();
    $animationCategoryList = AnimationCategory::where('status', 1)->get();
    $sizes = Size::where('status', 1)->get();

    return view('front.main.search_results', compact('sizes','products', 'categoryList', 'animationCategoryList', 'searchQuery'));
}

public function ajaxSearchFilter(Request $request)
{
    // Start with the base query for active products.
    $query = Product::where('status', 1);

    // Use the central helper to apply ALL filters, including the search query.
    $query = $this->applyFilters($request, $query);

    // Fetch and paginate the results
    $products = $query->with(['variants', 'productCategoryAssignment.category'])
        ->withCount('reviews')
        ->withAvg('reviews', 'rating')
        ->paginate(12);

    // Manually load categories for the current page of products
    // ... (your existing manual category loading logic can remain here if needed) ...
    
    $html = view('front.category.product_card_partial', compact('products'))->render();

    return response()->json([
        'html' => $html,
        'hasMorePages' => $products->hasMorePages(),
    ]);
}

    public function shop(Request $request)
{
    $query = Product::where('status', 1);
    $query = $this->applyFilters($request, $query);


    $products = $query->with(['category', 'variants', 'productCategoryAssignment.category']) ->withCount('reviews')
        ->withAvg('reviews', 'rating')
        ->latest()
        ->paginate(12);
        
    // 2. Manually load categories for the products on the current page
    $productIdsOnPage = $products->pluck('id');
    if ($productIdsOnPage->isNotEmpty()) {
        $assignments = AssignCategory::whereIn('product_id', $productIdsOnPage)->get()->keyBy('product_id');
        $categoryIds = $assignments->pluck('category_id')->unique();
        $categories = Category::whereIn('id', $categoryIds)->get()->keyBy('id');

        foreach ($products as $product) {
            $assignment = $assignments->get($product->id);
            if ($assignment) {
                $category = $categories->get($assignment->category_id);
                if ($category) {
                    $product->setRelation('category', $category);
                }
            }
        }
    }

    // Fetch data for the filter sidebar
    $sizes = Size::where('status', 1)->get();
    $categoryList = Category::where('status', 1)->whereNull('parent_id')->with('children')->get();
    $animationCategoryList = AnimationCategory::where('status', 1)->get();

    return view('front.main.shop', compact('products', 'categoryList', 'animationCategoryList', 'sizes'));
}

     /**
     * NEW dedicated function to handle AJAX filter requests for the shop page.
     */
    public function ajaxShopFilter(Request $request)
{
    $query = Product::where('status', 1);

    // শুধু একটি লাইন দিয়ে সব ফিল্টার প্রয়োগ করুন
    $query = $this->applyFilters($request, $query);

    $products = $query->with(['category', 'variants', 'productCategoryAssignment.category'])->withCount('reviews')
    ->withAvg('reviews', 'rating')->paginate(12);

    $html = view('front.category.product_card_partial', compact('products'))->render();

    return response()->json([
        'html' => $html,
        'hasMorePages' => $products->hasMorePages(),
    ]);
}

        public function subcategory(Request $request, $slug)
{
    $subcategory = Category::where('slug', $slug)->whereNotNull('parent_id')->firstOrFail();
    $category = $subcategory->parent;

    // 1. Get all product IDs for the base subcategory.
    $productIds = AssignCategory::where('category_id', $subcategory->id)->where('type','product_category')->pluck('product_id');

    // 2. Create the initial query for products in this subcategory.
    $query = Product::whereIn('id', $productIds)->where('status', 1);

    // 3. IMPORTANT: Apply all filters from the URL.
    $query = $this->applyFilters($request, $query);

    // 4. Paginate the final, filtered results.
    $products = $query->with(['variants', 'productCategoryAssignment.category'])
        ->withCount('reviews')
        ->withAvg('reviews', 'rating')
        ->paginate(12);

    // The rest of the function remains the same.
    $categoryList = Category::where('status', 1)->whereNull('parent_id')->with('children')->get();
    $sizes = Size::where('status', 1)->get();

    return view('front.category.subcategory', compact('subcategory', 'category', 'products', 'categoryList', 'sizes'));
}


/**
     * MODIFIED: Display the initial offer page with its bundle deals.
     */
    public function offer($slug)
    {
        $offer = BundleOffer::where('slug', $slug)->firstOrFail();

        // 1. Paginate the actual bundle deals for this offer
        $bundleDeals = BundleOfferProduct::where('bundle_offer_id', $offer->id)->paginate(12);

        // 2. Get all unique product IDs from the current page of deals
        $allProductIds = $bundleDeals->pluck('product_id')->flatten()->unique()->all();

        // 3. Fetch all related products in a single query for efficiency
        $productsCollection = Product::whereIn('id', $allProductIds) ->withCount('reviews')
        ->withAvg('reviews', 'rating')->get()->keyBy('id');

        // Fetch all active offers for the filter sidebar
        $offerList = BundleOffer::where('status', 1)->where('enddate', '>=', now())->get();

        return view('front.offer.show', compact('offer', 'bundleDeals', 'productsCollection', 'offerList'));
    }

    /**
     * MODIFIED: Handle AJAX requests to filter and display bundle deals.
     */
    public function filterOffers(Request $request)
{
    $request->validate(['offer_id' => 'required|integer|exists:bundle_offers,id']);

    // Start the query for bundle deals
    $query = BundleOfferProduct::where('bundle_offer_id', $request->offer_id);

    // MODIFIED: Add the price range filter to the query
    if ($request->filled('min_price') && $request->filled('max_price')) {
        $query->whereBetween('discount_price', [(float)$request->min_price, (float)$request->max_price]);
    }

    // Paginate the results
    $bundleDeals = $query->paginate(12);

    // The rest of the method remains the same
    $allProductIds = $bundleDeals->pluck('product_id')->flatten()->unique()->all();
    $productsCollection = Product::whereIn('id', $allProductIds) ->withCount('reviews')
        ->withAvg('reviews', 'rating')->get()->keyBy('id');
    $html = view('front.offer.bundle_card_partial', compact('bundleDeals', 'productsCollection'))->render();

    return response()->json([
        'html' => $html,
        'hasMorePages' => $bundleDeals->hasMorePages(),
    ]);
}


    /**
 * Handle AJAX requests for filtering on category and subcategory pages.
 */
public function filterProducts(Request $request)
{
    // Start with a query for all active products.
    $query = Product::where('status', 1);

    // Use the central helper function to apply all filters from the request.
    $query = $this->applyFilters($request, $query);

    // Paginate the final, filtered results.
    $products = $query->with(['variants', 'productCategoryAssignment.category'])
        ->withCount('reviews')
        ->withAvg('reviews', 'rating')
        ->paginate(12);

    // Manually load the correct category for each product on the current page.
    $productIdsOnPage = $products->pluck('id');
    if ($productIdsOnPage->isNotEmpty()) {
        $assignments = AssignCategory::whereIn('product_id', $productIdsOnPage)->get()->keyBy('product_id');
        $categoryIds = $assignments->pluck('category_id')->unique();
        $categories = Category::whereIn('id', $categoryIds)->get()->keyBy('id');

        foreach ($products as $product) {
            $assignment = $assignments->get($product->id);
            if ($assignment && isset($categories[$assignment->category_id])) {
                $product->setRelation('category', $categories[$assignment->category_id]);
            }
        }
    }

    $html = view('front.category.product_card_partial', compact('products'))->render();

    return response()->json([
        'html' => $html,
        'hasMorePages' => $products->hasMorePages(),
    ]);
}

     public function animationCategory(Request $request, $slug)
{
    $animationCategory = AnimationCategory::where('slug', $slug)->firstOrFail();

    // 1. Get all product IDs for the base animation category.
    $productIds = AssignCategory::where('category_id', $animationCategory->id)
        ->where('type', 'animation')
        ->pluck('product_id');

    // 2. Create the base query for these products.
    $query = Product::whereIn('id', $productIds)->where('status', 1);

    // 3. Apply all additional filters from the URL.
    $query = $this->applyFilters($request, $query);

    // 4. Paginate the final, filtered results.
    $products = $query->with(['variants', 'productCategoryAssignment.category'])
        ->withCount('reviews')
        ->withAvg('reviews', 'rating')
        ->paginate(12);

    // Fetch data for the filter sidebar (remains the same).
    $animationCategoryList = AnimationCategory::where('status', 1)->get();
    $sizes = Size::where('status', 1)->get();

    return view('front.animation.show', compact('animationCategory', 'products', 'animationCategoryList', 'sizes'));
}

    public function filterAnimationCategory(Request $request)
{
    // Start with a base query for all active products.
    $query = Product::where('status', 1);

    // Use the central helper to apply ALL filters from the request,
    // including the `animation_category_id`.
    $query = $this->applyFilters($request, $query);

    // Paginate the final, filtered results.
    $products = $query->with(['variants', 'productCategoryAssignment.category'])
        ->withCount('reviews')
        ->withAvg('reviews', 'rating')
        ->paginate(12);

    // Manually load categories for the current page of products
    // ... (your existing manual category loading logic can remain here) ...
    
    $html = view('front.category.product_card_partial', compact('products'))->render();

    return response()->json([
        'html' => $html,
        'hasMorePages' => $products->hasMorePages(),
    ]);
}
    
}
