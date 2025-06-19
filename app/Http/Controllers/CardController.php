<?php
namespace App\Http\Controllers;
use App\Models\Card;
use Illuminate\Http\Request;
use App\Http\Controllers\Controller;
use Illuminate\Support\Facades\DB;

class CardController extends Controller
{public function index()
{
    $cards = Card::all();

    foreach ($cards as $card) {
        try {
            // Exécuter la requête SQL
            $result = DB::select($card->value);

            // On prend uniquement la première colonne du premier résultat
            if (!empty($result)) {
                $firstRow = (array) $result[0];
                $card->result = reset($firstRow);  
            } else {
                $card->result = 'Aucun résultat';
            }
        } catch (\Exception $e) {
            $card->result = 'Erreur';
        }
    }

    return response()->json($cards);
}
    public function store(Request $request)
    {
        $request->validate([
            'label' => 'required',
            'value' => 'required',
            'description' => 'nullable',
        ]);

        return Card::create($request->all());
    }
    public function update(Request $request, $id)
{
    $card = Card::findOrFail($id);
    $card->label = $request->label;
    $card->description = $request->description;
    $card->value = $request->value;
    $card->save();

    return response()->json(['message' => 'Card mise à jour avec succès']);
}

public function destroy($id)
{
    $card = Card::findOrFail($id);
    $card->delete();

    return response()->json(['message' => 'Card supprimée avec succès']);
}

}
