<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class BundleOfferTier extends Model
{
    use HasFactory;

    protected $fillable = [
        'bundle_offer_id',
        'buy_quantity',
        'offer_price',
        'get_quantity',
    ];

    /**
     * Get the bundle offer that owns the tier.
     */
    public function bundleOffer()
    {
        return $this->belongsTo(BundleOffer::class);
    }
}
