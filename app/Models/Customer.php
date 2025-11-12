<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Illuminate\Notifications\Notifiable;
use Illuminate\Support\Facades\Hash;

class Customer extends Authenticatable
{
    use HasFactory, Notifiable;

    protected $fillable = [
        'old_customer_id',
        'reward_points',
        'user_id',
        'slug',
        'type',
        'name',
        'source',
        'email',
        'phone',
        'secondary_phone',
        'password',
        'address',
        'status',
    ];

    protected $hidden = [
        'password',
    ];

    public function addresses()
    {
        return $this->hasMany(CustomerAddress::class);
    }

    /**
 * Get all of the orders for the Customer.
 */
public function orders()
{
    return $this->hasMany(Order::class);
}

  /**
     * Get all of the reward point logs for the Customer.
     */
    public function rewardPointLogs()
    {
        return $this->hasMany(RewardPoint::class);
    }

    /**
     * Hash the password before saving.
     */
    public function setPasswordAttribute($value)
    {
        if ($value) {
            $this->attributes['password'] = Hash::make($value);
        }
    }
}
