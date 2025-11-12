<?php

namespace App\Providers;

use Illuminate\Support\Facades\View;
use Illuminate\Support\ServiceProvider;
use App\Models\Setting;
use App\Models\MenuItem;
use App\Models\SidebarMenu;
use App\Models\Category;
use App\Models\OffersectionSetting;
use App\Models\BundleOfferProduct;
use App\Models\Product;  
use Carbon\Carbon;

class ViewServiceProvider extends ServiceProvider
{
    public function boot(): void
    {
        // This composer shares data with all views in the 'front' directory.
        View::composer('front.*', function ($view) {
            // Fetch Header Settings
            $settings = Setting::pluck('value', 'key');
            $headerColor = $settings['header_color'] ?? '#FFFFFF';
            $menuLimit = $settings['menu_limit'] ?? 8; // Default to 8 if not set

            // Fetch Menu Items
            $menuItems = MenuItem::where('is_visible', true)
                                 ->orderBy('order')
                                 ->limit($menuLimit)
                                 ->get();
            
            // Pass all variables to the view
            $view->with('headerColor', $headerColor);
            $view->with('menuItems', $menuItems);
        });

        // NEW: Composer specifically for the sidebar menu
        View::composer('front.*', function ($view) {
            // Get the ordered list of categories from your sidebar control table
          

            // Fetch the actual Category models with their subcategories,
            // ordered according to your admin panel settings.
            $sidebarCategories = Category::whereNull('parent_id') // <-- Fetch only parents
                                         ->where('status', 1)        // <-- Ensure parent is active
                                         ->with(['children' => function ($query) {
                                             $query->where('status', 1); // <-- Ensure children are active
                                         }])
                                         // ->orderBy('order') // <-- Optional: Add if you have an order column
                                         ->get();

            $view->with('sidebarCategories', $sidebarCategories);
        });

        View::composer('front.*', function ($view) {
            $timezone = 'Asia/Dhaka';
            $now = Carbon::now($timezone);

            // MODIFIED QUERY: Only load the 'bundleOffer' if its 'enddate' is in the future.
            $offerSectionSetting = OffersectionSetting::with(['bundleOffer' => function ($query) use ($now) {
                $query->where('status', 1)->where('enddate', '>=', $now);
            }])->first();
            
            $offerDealsGlobal = collect();
            $products = collect();
            $remaining = ['days' => 0, 'hours' => 0, 'minutes' => 0, 'seconds' => 0];
            $dealEndDateISO = null;

            // This condition now automatically handles expired offers,
            // because $offerSectionSetting->bundleOffer will be null if the date has passed.
            if ($offerSectionSetting && $offerSectionSetting->bundleOffer) {
                $offerDealsGlobal = BundleOfferProduct::where('bundle_offer_id', $offerSectionSetting->bundleOffer->id)->get();
                $allProductIds = $offerDealsGlobal->pluck('product_id')->flatten()->unique()->all();
                $products = Product::whereIn('id', $allProductIds)->get()->keyBy('id');

                // --- Timer & Date Logic ---
                $sellEndDateObject = Carbon::parse($offerSectionSetting->bundleOffer->enddate, $timezone)->endOfDay();

                if ($now->lt($sellEndDateObject)) {
                    $diff = $now->diff($sellEndDateObject);
                    $remaining = [
                        'days' => $diff->d,
                        'hours' => $diff->h,
                        'minutes' => $diff->i,
                        'seconds' => $diff->s
                    ];
                }
    
                $dealEndDateISO = $sellEndDateObject->toIso8601String();
                // --- Timer Logic End ---
            }
            
            $view->with('dealEndDateISO', $dealEndDateISO);
            $view->with('remaining', $remaining);
            $view->with('offerSectionSetting', $offerSectionSetting);
            $view->with('offerDealsGlobal', $offerDealsGlobal);
            $view->with('offerProducts', $products);
        });
    }
}