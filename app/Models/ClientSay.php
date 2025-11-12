<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Factories\HasFactory;
class ClientSay extends Model
{
    use HasFactory;

    protected $fillable = [
        'title',
        'des',
        'youtube_video_link',
        'status',
    ];
}
