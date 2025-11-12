<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Factories\HasFactory;
class SystemInformation extends Model
{
    use HasFactory;

    protected $fillable = [

            'ins_name',
            'logo',
            'branch_id',
            'designation_id',
            'keyword',
            'description',
            'develop_by',
            'icon',
            'address',
            'email',
        'email_one', // Added secondary email
        'phone',
        'phone_one', // Added secondary phone
            'main_url',
            'admin_url',
            'tax',
            'charge',
            'usdollar',

    ];
}
