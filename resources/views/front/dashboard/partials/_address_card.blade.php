<div class="spotlight_user_profile_address-card card mb-3" id="address-card-{{ $address->id }}">
    <div class="card-body">
        <div class="d-flex align-items-center mb-2">
            @php
                $addressTypeLabel = $address->address_type . ' Address';
            @endphp
            <span class="badge bg-light text-secondary me-2">{{ $addressTypeLabel }}</span>
            
            @if($address->is_default)
                <span class="badge bg-info">Default</span>
            @endif
        </div>
        <div class="d-flex justify-content-between align-items-center">
            <div class="d-flex align-items-center">
                @if($address->address_type == 'Office')
                    <i class="bi bi-building fs-3 me-3 text-secondary"></i>
                @else
                    <i class="bi bi-house-fill fs-3 me-3 text-secondary"></i>
                @endif
                <div>
                    {{-- Name and phone are associated with the main user, not the specific address --}}
                    <h6 class="mb-0">{{ $user->name }}</h6>
                    <p class="mb-0 text-muted">{{ $user->phone }}</p>
                    <p class="mb-0 text-muted">{{ $address->address }}</p>
                </div>
            </div>
            <div class="btn-group">
                <button class="btn btn-outline-secondary dropdown-toggle" type="button" data-bs-toggle="dropdown" aria-expanded="false">
                    <i class="bi bi-three-dots"></i>
                </button>
                <ul class="dropdown-menu dropdown-menu-end">
                    <li><a class="dropdown-item edit-address-btn" href="#" data-address='{{ json_encode($address) }}'>Edit</a></li>
                    @if(!$address->is_default)
                        <li><a class="dropdown-item set-default-btn" href="#" data-id="{{ $address->id }}">Set as Default</a></li>
                        <li><hr class="dropdown-divider"></li>
                    @endif
                    <li><a class="dropdown-item delete-address-btn text-danger" href="#" data-id="{{ $address->id }}">Delete</a></li>
                </ul>
            </div>
        </div>
    </div>
</div>

