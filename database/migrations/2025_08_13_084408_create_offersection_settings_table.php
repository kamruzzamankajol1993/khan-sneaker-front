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
        Schema::create('offersection_settings', function (Blueprint $table) {
            $table->id();
            $table->boolean('is_visible')->default(true);
            $table->string('background_color')->default('#FFFFFF');
            $table->foreignId('bundle_offer_id')->nullable()->constrained()->onDelete('set null');
            $table->string('route')->nullable()->comment('e.g., route for the offer section');
            $table->timestamps();
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('offersection_settings');
    }
};
