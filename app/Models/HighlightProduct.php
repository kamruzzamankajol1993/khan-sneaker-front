<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class HighlightProduct extends Model
{
    use HasFactory;

    protected $fillable = [
        'product_id',
        'title',
        'section',
    ];

    public function product()
    {
        return $this->belongsTo(Product::class);
    }
}
