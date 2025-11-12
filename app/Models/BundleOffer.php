<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class BundleOffer extends Model
{
    use HasFactory;

    protected $fillable = [
        'name',
           'slug',
        'title',
        'status',
        'is_free_delivery',
        'image',
        'startdate',
        'enddate',
    ];
protected $casts = [
        'startdate' => 'datetime',
        'enddate' => 'datetime',
        'is_free_delivery' => 'boolean',
    ];
    /**
     * Get the product sets for the bundle offer.
     */
    public function bundleOfferProducts()
    {
        return $this->hasMany(BundleOfferProduct::class);
    }
}
