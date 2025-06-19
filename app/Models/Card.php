<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Card extends Model
{
    // Par défaut, Laravel utilise le nom de table au pluriel => "cards"

    protected $fillable = [
        'label',
        'description',
        'value'
    ];
}
