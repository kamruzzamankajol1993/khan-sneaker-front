<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('hero_right_sliders', function (Blueprint $table) {
            $table->id();
            $table->string('position')->unique(); // 'top', 'bottom_left', 'bottom_right'
            $table->string('title')->nullable();
            $table->string('subtitle')->nullable();
            $table->string('image')->nullable();
            $table->boolean('status')->default(true);

            // For the 'top' section
            $table->foreignId('bundle_offer_id')->nullable()->constrained('bundle_offers')->onDelete('set null');

            // Polymorphic relationship for 'bottom' sections (links to Category or ExtraCategory)
            $table->unsignedBigInteger('linkable_id')->nullable();
            $table->string('linkable_type')->nullable();
            
            $table->timestamps();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('hero_right_sliders');
    }
};