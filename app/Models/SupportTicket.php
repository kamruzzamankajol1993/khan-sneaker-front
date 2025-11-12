<?php

namespace App;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class SupportTicket extends Model
{
    use HasFactory;
    protected $fillable = ['category_id', 'question', 'answer', 'is_faq', 'status'];

    public function category()
    {
        return $this->belongsTo(SupportPageCategory::class, 'category_id');
    }
}