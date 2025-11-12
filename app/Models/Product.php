<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\SoftDeletes;
use Illuminate\Support\Str;

class Product extends Model
{
    use HasFactory, SoftDeletes;

    /**
     * The attributes that are mass assignable.
     *
     * @var array<int, string>
     */
    protected $fillable = [
        'name',
        'slug',
        'product_code',
        'brand_id',
        'category_id',
        'subcategory_id',
        'sub_subcategory_id',
        'fabric_id',
         'view_count',
        'unit_id',
        'description',
        'base_price',
        'discount_price',
        'purchase_price',
        'main_image',
        'thumbnail_image',
        'real_image',
        'status',
        'is_free_delivery',
    ];


    protected $casts = [
        'thumbnail_image' => 'array', // This is the important change
        'main_image' => 'array',
        'real_image' => 'array',
        'is_free_delivery' => 'boolean',
    ];

     public function productCategoryAssignment()
    {
        return $this->hasOne(AssignCategory::class)->where('type', 'product_category');
    }

    /**
     * Get all of the variants for the Product.
     */
    public function variants()
    {
        return $this->hasMany(ProductVariant::class);
    }

    /**
     * Get the brand that owns the Product.
     */
    public function brand()
    {
        return $this->belongsTo(Brand::class);
    }

    /**
     * Get the category that owns the Product.
     */
    public function category()
    {
        return $this->belongsTo(Category::class);
    }

    /**
     * Get the subcategory that owns the Product.
     */
    public function subcategory()
    {
        return $this->belongsTo(Subcategory::class);
    }

    /**
     * Get the sub-subcategory that owns the Product.
     */
    public function subSubcategory()
    {
        return $this->belongsTo(SubSubcategory::class, 'sub_subcategory_id');
    }

    /**
     * Get the fabric that owns the Product.
     */
    public function fabric()
    {
        return $this->belongsTo(Fabric::class);
    }

    /**
     * Get the unit that owns the Product.
     */
    public function unit()
    {
        return $this->belongsTo(Unit::class);
    }

     public function assignChart()
    {
        return $this->hasOne(AssignChart::class);
    }

     public function assigns()
    {
        return $this->hasMany(AssignCategory::class);
    }

     public function reviews()
    {
        return $this->hasMany(ProductReview::class)->where('is_approved', true);
    }
    
    /**
     * Accessor to get the average rating.
     * Use ->withAvg('reviews', 'rating') in your controller for better performance.
     *
     * @return float
     */
    public function getAverageRatingAttribute()
    {
        // The 'reviews_avg_rating' attribute is loaded by withAvg() in the controller
        return round($this->reviews_avg_rating, 1) ?? 0;
    }


    /**
     * Boot the model.
     */
    protected static function boot()
    {
        parent::boot();
        static::creating(function ($product) {
            if (empty($product->slug)) {
                $product->slug = Str::slug($product->name);
            }
        });
    }
}
