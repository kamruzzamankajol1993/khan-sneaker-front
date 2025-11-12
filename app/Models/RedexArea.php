<?php

namespace App\Models;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class RedexArea extends Model
{
    use HasFactory;

    protected $fillable = [
    
         'District',
         'Upazila_Thana',
         'Delivery_Charge',
    ];
}
