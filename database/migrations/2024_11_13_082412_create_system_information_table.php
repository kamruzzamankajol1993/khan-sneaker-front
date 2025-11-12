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
        Schema::create('system_information', function (Blueprint $table) {
            $table->id();
            $table->string('ins_name')->nullable();
            $table->string('logo')->nullable();
            $table->string('branch_id')->nullable();
            $table->string('icon')->nullable();
            $table->string('address')->nullable();
            $table->string('keyword')->nullable();
            $table->text('description')->nullable();
            $table->string('email')->nullable();
            $table->string('phone',11)->nullable();
            $table->string('main_url')->nullable();
            $table->string('tax')->nullable();
            $table->string('develop_by')->nullable();
            $table->string('charge')->nullable();
            $table->string('usdollar')->nullable();
            $table->timestamps();
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('system_information');
    }
};
