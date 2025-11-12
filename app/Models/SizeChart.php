<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class SizeChart extends Model
{
    use HasFactory;

    protected $fillable = ['name', 'status'];

    public function entries()
    {
        return $this->hasMany(SizeChartEntry::class);
    }
}
