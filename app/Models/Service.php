<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Factories\HasFactory;
class Service extends Model
{
    use HasFactory;
     protected $fillable = [
        'title',
        'slug',
        'des',
        'image',
        'price',
        'status',
    ];

    public function tickets(): MorphMany
{
    return $this->morphMany(GeneralTicket::class, 'ticketable', 'ticket_type', 'offer_or_service_id');
}
}
