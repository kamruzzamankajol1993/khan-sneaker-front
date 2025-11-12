<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class HomepageSection extends Model
{
    use HasFactory;

    protected $fillable = [
        'category_id',
        'image',
        'title',
        'row_identifier',
        'status',
    ];

    /**
     * Get the category associated with this section.
     */
    public function category()
    {
        return $this->belongsTo(Category::class);
    }
}