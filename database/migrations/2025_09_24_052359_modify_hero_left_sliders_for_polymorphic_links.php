<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::table('hero_left_sliders', function (Blueprint $table) {
            // Remove the old column
            $table->dropColumn('product_or_category_id');

            // Add the new columns for a polymorphic relationship
            $table->unsignedBigInteger('linkable_id')->after('image');
            $table->string('linkable_type')->after('linkable_id');
        });
    }

    public function down(): void
    {
        Schema::table('hero_left_sliders', function (Blueprint $table) {
            $table->dropColumn(['linkable_id', 'linkable_type']);
            $table->string('product_or_category_id');
        });
    }
};