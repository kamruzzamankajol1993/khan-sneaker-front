<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class AssignChartEntry extends Model
{
    use HasFactory;

    protected $fillable = [
        'assign_chart_id',
        'size',
        'length',
        'width',
        'shoulder',
        'sleeve',
    ];

    /**
     * Get the assigned chart that this entry belongs to.
     */
    public function assignChart()
    {
        return $this->belongsTo(AssignChart::class);
    }
}
