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
        Schema::create('orders', function (Blueprint $table) {
            $table->id();
            $table->foreignId('customer_id')->constrained()->onDelete('cascade');
            $table->string('invoice_no')->unique();
            $table->string('delivery_type')->nullable(); // e.g., standard, express
            $table->decimal('subtotal', 10, 2);
            $table->decimal('shipping_cost', 10, 2)->default(0);
            $table->decimal('discount', 10, 2)->default(0);
            $table->decimal('total_amount', 10, 2);
            $table->decimal('total_pay', 10, 2)->default(0);
            $table->decimal('due', 10, 2)->default(0);
            $table->decimal('cod', 10, 2)->default(0);
            $table->string('old_id')->nullable();
            $table->string('status')->default('pending'); // e.g., pending, processing, shipped, delivered, cancelled
            $table->text('shipping_address');
            $table->text('billing_address')->nullable();
            $table->string('currency')->default('BDT');
            $table->string('payment_method')->nullable();
            $table->string('payment_status')->default('pending'); // e.g., pending, paid, failed
            $table->string('payment_term')->nullable(); // e.g., COD, Online
            $table->string('order_from')->nullable(); // e.g., web, app
            $table->string('trxID')->nullable(); // Transaction ID
            $table->text('statusMessage')->nullable(); // e.g., reason for cancellation
            $table->text('notes')->nullable(); // Internal notes
            $table->timestamps();
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('orders');
    }
};
