<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('slider_controls', function (Blueprint $table) {
            $table->id();
            $table->string('section_key')->unique()->comment('e.g., main_slider, top_banner, bottom_banners');
            $table->string('title');
            $table->json('product_ids')->nullable(); // To store an array of product IDs
            $table->boolean('is_visible')->default(true);
            $table->timestamps();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('slider_controls');
    }
};