<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class SizeChartEntry extends Model
{
    use HasFactory;

    protected $fillable = [
        'size_chart_id',
        'size',
        'length',
        'width',
        'shoulder',
        'sleeve',
    ];

    public function sizeChart()
    {
        return $this->belongsTo(SizeChart::class);
    }
}
