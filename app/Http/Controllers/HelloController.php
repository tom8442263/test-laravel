<?php
namespace App\Http\Controllers;
use Illuminate\Http\Request;

class HelloController extends Controller
{
    public function index(Request $request)
    {
        $text = "Hello Cruel World";
        $itemsPerPage = 10; // Number of items per page
        
        // Simulate some data for demonstration
        $data = collect(range(1, 30)); // Creates collection [1, 2, ..., 30]
        
        // Paginate the data
        $paginatedData = $data->paginate($itemsPerPage);
        
        return view('hello_index', [
            'text' => $text,
            'data' => $paginatedData
        ]);
    }
}