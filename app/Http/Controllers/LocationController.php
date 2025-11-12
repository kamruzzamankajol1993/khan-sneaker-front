<?php

namespace App\Http\Controllers;

use App\Models\RedexArea;
use Illuminate\Http\Request;

class LocationController extends Controller
{
    /**
     * Get a unique, sorted list of all districts.
     */
    public function getDistricts()
    {
        // Using query builder for efficiency
        $districts = RedexArea::select('District')
            ->distinct()
            ->orderBy('District', 'asc')
            ->pluck('District');
            
        return response()->json($districts);
    }

    /**
     * Get all upazilas for a given district.
     */
    public function getUpazilas(Request $request)
    {
        $request->validate(['district' => 'required|string']);

        $district = $request->query('district');

        $upazilas = RedexArea::where('District', $district)
            ->orderBy('Upazila_Thana', 'asc')
            ->pluck('Upazila_Thana');

        return response()->json($upazilas);
    }
}