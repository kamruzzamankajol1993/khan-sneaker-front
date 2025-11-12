<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class Coupon extends Model
{
    use HasFactory;

    protected $fillable = [
        'code',
        'type',
        'value',
        'min_amount',
        'user_type',
        'product_ids',
        'category_ids',
        'usage_limit',
        'times_used',
        'expires_at',
        'status',
    ];

    protected $casts = [
        'product_ids' => 'array',
        'category_ids' => 'array',
        'expires_at' => 'date',
        'status' => 'boolean',
    ];
}
