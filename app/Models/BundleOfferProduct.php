<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class BundleOfferProduct extends Model
{
    use HasFactory;

    /**
     * The table associated with the model.
     *
     * @var string
     */
    protected $table = 'bundle_offer_product';

    /**
     * The attributes that are mass assignable.
     *
     * @var array<int, string>
     */
    protected $fillable = [
        'bundle_offer_id',
        'title',
        'product_id',
        'discount_price',
        'buy_quantity',
        'get_quantity',
         'view_count',
    ];

    /**
     * The attributes that should be cast.
     *
     * @var array
     */
    protected $casts = [
        'product_id' => 'array', // Automatically handles JSON encoding and decoding
    ];

    /**
     * Get the bundle offer that owns the product set.
     */
    public function bundleOffer()
    {
        return $this->belongsTo(BundleOffer::class);
    }


    
}