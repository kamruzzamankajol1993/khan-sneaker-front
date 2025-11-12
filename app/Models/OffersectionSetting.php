<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class OffersectionSetting extends Model
{
    use HasFactory;

    protected $fillable = [
        'is_visible',
        'background_color',
        'bundle_offer_id',
        'route',
    ];

    /**
     * Get the bundle offer associated with the setting.
     */
    public function bundleOffer()
    {
        return $this->belongsTo(BundleOffer::class);
    }
}