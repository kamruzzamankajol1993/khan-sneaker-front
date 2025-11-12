<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Str;

class AnimationCategory extends Model
{
    use HasFactory;

    protected $fillable = [
        'name',
        'slug',
        'image',
        'status',
    ];

    protected static function boot()
    {
        parent::boot();
        static::creating(function ($item) {
            $item->slug = Str::slug($item->name);
        });
    }
}
