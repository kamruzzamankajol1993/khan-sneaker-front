<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::table('menu_items', function (Blueprint $table) {
            // This column will store the ID of the original Category, ExtraCategory, etc.
            $table->unsignedBigInteger('source_id')->nullable()->after('id');
            
            // Add an index for better performance
            $table->index(['source_id', 'type']);
        });
    }

    public function down(): void
    {
        Schema::table('menu_items', function (Blueprint $table) {
            $table->dropIndex(['source_id', 'type']);
            $table->dropColumn('source_id');
        });
    }
};