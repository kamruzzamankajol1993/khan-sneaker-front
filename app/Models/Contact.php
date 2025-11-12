<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Factories\HasFactory;
class Contact extends Model
{
    use HasFactory;

    protected $fillable = [
        'phone_one',
            'phone_two',
            'email_one',
            'email_two',
           'address_one',
           'address_two',
    ];
}
