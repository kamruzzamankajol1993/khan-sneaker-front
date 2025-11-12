<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Run the migrations.
     *
     * @return void
     */
    public function up()
    {
        // This table links products to a bundle offer
        Schema::create('bundle_offer_product', function (Blueprint $table) {
            $table->id();
            $table->foreignId('bundle_offer_id')->constrained()->onDelete('cascade');
            $table->string('title')->nullable();
            $table->json('product_id');
            $table->decimal('discount_price', 8, 2)->nullable();
            $table->integer('buy_quantity')->default(1);
            $table->integer('get_quantity')->nullable()->default(0);
            $table->timestamps();
        });
    }

    /**
     * Reverse the migrations.
     *
     * @return void
     */
    public function down()
    {
        Schema::dropIfExists('bundle_offer_product');
    }
};
