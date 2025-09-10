<h1>{{ $text }}</h1>

<div class="pagination-container">
    @foreach($data as $item)
        <div>{{ $item }}</div>
    @endforeach
    
    {{ $data->links() }}
</div>