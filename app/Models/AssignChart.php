<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class AssignChart extends Model
{
    use HasFactory;

    protected $fillable = [
        'product_id',
        'size_chart_id',
    ];

    /**
     * Get the product that this assigned chart belongs to.
     */
    public function product()
    {
        return $this->belongsTo(Product::class);
    }

    /**
     * Get the original default size chart.
     */
    public function originalSizeChart()
    {
        return $this->belongsTo(SizeChart::class, 'size_chart_id');
    }

    /**
     * Get all of the entries for the assigned chart.
     */
    public function entries()
    {
        return $this->hasMany(AssignChartEntry::class);
    }
}
