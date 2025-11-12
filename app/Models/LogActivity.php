<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Factories\HasFactory;
class LogActivity extends Model
{
    use HasFactory;
    protected $fillable = [

        'subject', 'url', 'method', 'ip', 'agent', 'user_id','activity_time'

    ];
}
