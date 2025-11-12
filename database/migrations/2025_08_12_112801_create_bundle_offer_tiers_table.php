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
        Schema::create('bundle_offer_tiers', function (Blueprint $table) {
            $table->id();
            $table->foreignId('bundle_offer_id')->constrained()->onDelete('cascade');
            $table->integer('buy_quantity')->comment('e.g., User must buy this many items');
            $table->decimal('offer_price', 10, 2);
            $table->integer('get_quantity')->default(0)->comment('e.g., User gets this many items free');
            $table->timestamps();
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('bundle_offer_tiers');
    }
};
