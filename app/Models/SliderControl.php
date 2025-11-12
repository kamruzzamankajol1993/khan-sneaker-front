<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class SliderControl extends Model
{
    use HasFactory;

    protected $fillable = [
        'section_key',
        'title',
        'product_ids',
        'is_visible',
    ];

    protected $casts = [
        'product_ids' => 'array',
        'is_visible' => 'boolean',
    ];
}