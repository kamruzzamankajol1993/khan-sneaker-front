<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class FeaturedCategory extends Model
{
    use HasFactory;

    /**
     * The attributes that are mass assignable.
     *
     * @var array<int, string>
     */
    protected $fillable = [
        'key',
        'value',
    ];

    /**
     * The attributes that should be cast.
     *
     * This will automatically convert the JSON string from the database
     * into a PHP array and vice-versa.
     *
     * @var array<string, string>
     */
    protected $casts = [
        'value' => 'array',
    ];
}