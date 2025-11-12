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
        Schema::create('product_variants', function (Blueprint $table) {
            $table->id();
             $table->foreignId('product_id')->constrained()->onDelete('cascade');
            $table->foreignId('color_id')->nullable()->constrained()->onDelete('set null');
            $table->string('main_image')->nullable();
            $table->string('variant_image')->nullable(); // For color-specific image
            $table->json('sizes'); // To store multiple sizes like [{"size_id": 1, "quantity": 10}, {"size_id": 2, "quantity": 12}]
            $table->string('variant_sku')->unique()->nullable();
            $table->decimal('additional_price', 10, 2)->default(0);
            $table->timestamps();
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('product_variants');
    }
};
