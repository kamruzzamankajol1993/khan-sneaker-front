<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class HeroLeftSlider extends Model
{
    use HasFactory;

    // Update the fillable array
    protected $fillable = ['title', 'subtitle', 'image', 'linkable_id', 'linkable_type', 'status'];
    
    /**
     * Define the polymorphic relationship.
     * This allows a slider to link to different models (Product, Category, etc.).
     */
    public function linkable()
    {
        return $this->morphTo();
    }
}