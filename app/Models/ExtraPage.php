<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Factories\HasFactory;
class ExtraPage extends Model
{
    use HasFactory;

    protected $fillable = [
         'privacy_policy',
         'term_condition',
         'return_pollicy',
    ];
}
