<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class HeroRightSlider extends Model
{
    use HasFactory;

    protected $fillable = [
        'position', 'title', 'subtitle', 'image', 'status', 
        'bundle_offer_id', 'linkable_id', 'linkable_type'
    ];

    public function bundleOffer()
    {
        return $this->belongsTo(BundleOffer::class);
    }
    
    public function linkable()
    {
        return $this->morphTo();
    }
}