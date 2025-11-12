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
        Schema::create('bundle_offers', function (Blueprint $table) {
            $table->id();
            $table->string('name')->comment('e.g., Bundle Offer');
            $table->string('title')->comment('e.g., Summer T-Shirt Deal');
            $table->string('image')->nullable()->after('title');
            $table->string('startdate')->nullable()->after('image');
            $table->string('enddate')->nullable()->after('startdate');
            $table->boolean('status')->default(true);
            $table->timestamps();
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('bundle_offers');
    }
};
