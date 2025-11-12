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
        Schema::create('coupons', function (Blueprint $table) {
            $table->id();
            $table->string('code')->unique(); // The unique coupon code (e.g., "SUMMER25")
            $table->enum('discount_type', ['percentage', 'fixed'])->default('percentage'); // Type of discount: percentage or fixed amount
            $table->decimal('discount_value', 8, 2); // The value of the discount
            $table->timestamp('expires_at')->nullable(); // Optional expiration date for the coupon
            $table->integer('usage_limit')->unsigned()->nullable(); // How many times the coupon can be used in total
            $table->integer('usage_limit_per_user')->unsigned()->nullable(); // How many times a single user can use this coupon
            $table->integer('times_used')->unsigned()->nullable(); // How many times the coupon has been used
            $table->boolean('is_active')->default(true); // Status of the coupon
            $table->timestamps();
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('coupons');
    }
};
