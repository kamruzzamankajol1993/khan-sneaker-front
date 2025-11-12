<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class ProductVariant extends Model
{
    use HasFactory;

    /**
     * The attributes that are mass assignable.
     *
     * @var array<int, string>
     */
    protected $fillable = [
        'product_id',
        'color_id',
        'variant_image',
        'main_image',
        'sizes',
        'variant_sku',
        'additional_price',
    ];

    /**
     * The attributes that should be cast.
     *
     * @var array
     */
   

    protected $casts = [
        'sizes' => 'array',
        'main_image' => 'array',      // Add this line
        'variant_image' => 'array',   // Add this line as well to prevent a similar error
    ];

    protected $appends = ['detailed_sizes'];

    /**
     * Accessor for detailed sizes.
     * This method fetches the names for the size IDs stored in the `sizes` JSON column.
     *
     * @return array
     */
    public function getDetailedSizesAttribute(): array
    {
        $sizesData = $this->sizes;
        if (empty($sizesData) || !is_array($sizesData)) {
            return [];
        }

        $sizeIds = array_column($sizesData, 'size_id');
        if (empty($sizeIds)) {
            return [];
        }

        $sizesMasterList = Size::whereIn('id', $sizeIds)->get()->keyBy('id');
        
        $detailedSizes = [];
        foreach ($sizesData as $sizeEntry) {
            if (isset($sizeEntry['size_id']) && $sizesMasterList->has($sizeEntry['size_id'])) {
                $detailedSizes[] = [
                    'id'       => $sizeEntry['size_id'],
                    'name'     => $sizesMasterList[$sizeEntry['size_id']]->name,
                    'quantity' => $sizeEntry['quantity'],
                ];
            }
        }

        return $detailedSizes;
    }

    /**
     * Get the product that this variant belongs to.
     */
    public function product()
    {
        return $this->belongsTo(Product::class);
    }

    /**
     * Get the color for this variant.
     */
    public function color()
    {
        return $this->belongsTo(Color::class);
    }

    public function bundleOfferProducts()
{
    return $this->hasMany(BundleOfferProduct::class);
}
}
