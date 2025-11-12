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
        Schema::create('featured_categories', function (Blueprint $table) {
            $table->id();
            $table->string('key')->unique(); // e.g., 'first_row_categories', 'second_row_categories'
            $table->text('value')->nullable(); // Stores a JSON array of category IDs
            $table->timestamps();
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('featured_categories');
    }
};