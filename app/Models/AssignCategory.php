<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class AssignCategory extends Model
{
    use HasFactory;

    protected $fillable = [
        'product_id',
        'category_id',
        'category_name',
        'type',
    ];

   public function product()
    {
        return $this->belongsTo(Product::class);
    }

     /**
     * NEW: Add this relationship to get the category details.
     */
    public function category()
    {
        return $this->belongsTo(Category::class);
    }
}
