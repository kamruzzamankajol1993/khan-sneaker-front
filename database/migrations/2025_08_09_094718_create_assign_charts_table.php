<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Run the migrations.
     */
    public function up(): void
    {
        Schema::create('assign_charts', function (Blueprint $table) {
            $table->id();
             // Link to the product. Assuming you have a 'products' table.
            $table->foreignId('product_id');
            // Link to the original default size chart for reference
            $table->foreignId('size_chart_id');
            $table->timestamps();
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('assign_charts');
    }
};
