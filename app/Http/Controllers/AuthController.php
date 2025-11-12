<?php

namespace App\Http\Controllers;

use App\Models\Customer;
use App\Models\CustomerAddress;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB; // <-- Ensure this is present
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Facades\Password;
use Illuminate\Support\Facades\Validator;
use Illuminate\Support\Str;
use Illuminate\Support\Facades\File; 
use Mpdf\Mpdf;
use Exception; // <-- Ensure this is present
use GuzzleHttp\Client; 
use Illuminate\Support\Facades\Cookie;
use Illuminate\Support\Facades\Session;
class AuthController extends Controller
{

    /**
     * A private helper function to send an OTP via ADN SMS Gateway.
     */
    private function sendSmsOtp($phone, $otp)
    {
$cleanPhoneNumber = trim($phone);
       // dd($phone);
        try {
            $client = new Client();
            $url = 'https://portal.adnsms.com/api/v1/secure/send-sms';

            $response = $client->post($url, [
                'form_params' => [
                    'api_key' => 'KEY-ngd8usyr9mj7hgoazbj7qggib5x9ztud',
                    'api_secret' => 'jXxdbA3eiuj2EEGa',
                    'request_type' => 'OTP',
                    'message_type' => 'TEXT',
                    'mobile'       => (string) $cleanPhoneNumber,
                    'message_body' => 'Your Spotlight Attires verification code is: ' . $otp,
                ]
            ]);

            $responseBody = json_decode($response->getBody(), true);

            // Check the API response code from ADN SMS. '200' usually means success.
            if (isset($responseBody['api_response_code']) && $responseBody['api_response_code'] == "200") {
                 return true;
            } else {
                 \Log::error('ADN SMS API Error: ' . json_encode($responseBody));
                 return false;
            }
        } catch (Exception $e) {
            \Log::error("SMS sending failed: " . $e->getMessage());
            return false;
        }
    }


    // --- ADD THIS NEW METHOD FOR PROFILE PICTURE UPDATES ---
    public function updateProfilePicture(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'profile_image' => 'required|image|mimes:jpeg,png,jpg,gif|max:2048',
        ]);

        if ($validator->fails()) {
            return response()->json(['success' => false, 'message' => $validator->errors()->first()], 422);
        }

        $user = Auth::user();

        if ($request->hasFile('profile_image')) {
            // Delete the old image if it exists
            if ($user->image && File::exists(public_path($user->image))) {
                File::delete(public_path($user->image));
            }

            // Store the new image
            $image = $request->file('profile_image');
            $imageName = 'customer-' . $user->id . '-' . time() . '.' . $image->extension();
            $image->move(public_path('uploads/customer_images'), $imageName);
            $path = 'uploads/customer_images/' . $imageName;

            // Update the user record
            $user->image = $path;
            $user->save();

            return response()->json([
                'success' => true, 
                'message' => 'Profile picture updated successfully!',
                'image_url' => asset('public/' . $path)
            ]);
        }

        return response()->json(['success' => false, 'message' => 'No image file found.'], 400);
    }
    /**
     * Handle a login request.
     */
    public function login(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'email'    => 'required|string',
            'password' => 'required|string',
        ]);

        if ($validator->fails()) {
            return response()->json(['success' => false, 'errors' => $validator->errors()], 422);
        }

        $loginInput = $request->input('email');
        $loginField = filter_var($loginInput, FILTER_VALIDATE_EMAIL) ? 'email' : 'phone';

        $credentials = [
            $loginField => $loginInput,
            'password'  => $request->input('password')
        ];

        $user = User::where($loginField, $loginInput)->first();

        if ($user) {
            if ($user->status == 0) {
                return response()->json(['success' => false, 'message' => 'This account is inactive.'], 403);
            }
            if ($user->user_type == 2) {
                 return response()->json(['success' => false, 'message' => 'The provided credentials do not match our records.'], 401);
            }
        }

        // Attempt to log in
        if (Auth::attempt($credentials)) {
            $request->session()->regenerate();
            return response()->json(['success' => true, 'redirect_url' => route('dashboard.user')]);
        }

        return response()->json(['success' => false, 'message' => 'The provided credentials do not match our records.'], 401);
    }

   /**
     * Handle a registration request and send OTP.
     */
     public function register(Request $request)
    {
        // Prepend '0' to the 10-digit phone number to make it 11 digits
        if ($request->has('phone')) {
            $request->merge([
                'phone' => '0' . $request->phone
            ]);
        }
        $formattedPhone = $request->phone;

        // --- MODIFIED VALIDATION LOGIC ---
        $existingCustomer = Customer::where('phone', $formattedPhone)->first();
        $existingUser = User::where('phone', $formattedPhone)->first();

        $rules = [
            'name'      => 'required|string|max:255',
            'email'     => 'nullable|string|email|max:255',
            'phone'     => 'required|string|digits:11',
            'password'  => 'required|string|min:8|confirmed',
        ];

        if ($existingCustomer && !$existingUser) {
            // Scenario 1: Customer exists, User does not.
            // Only validate email uniqueness against the users table.
            $rules['email'] .= '|unique:users,email';
        } else {
            // Scenario 2: New customer OR (Customer exists AND User exists).
            // Apply all unique rules. This will correctly fail if the user is already fully registered.
            $rules['email'] .= '|unique:users,email|unique:customers,email';
            $rules['phone'] .= '|unique:users,phone|unique:customers,phone';
        }

        $validator = Validator::make($request->all(), $rules);
        // --- END MODIFIED VALIDATION LOGIC ---


        if ($validator->fails()) {
            return response()->json(['success' => false, 'errors' => $validator->errors()], 422);
        }

        $tempUserData = $request->except('password_confirmation', '_token', 'image');
        
        // If email is not provided, generate a unique one using the phone number.
        if (empty($request->email)) {
            $tempUserData['email'] = $request->phone . '@guest.user';
        }
        
        if ($request->hasFile('image')) {
            $imageName = time().'.'.$request->image->extension();  
            $request->image->move(public_path('uploads/customer_images'), $imageName);
            $tempUserData['image_path'] = 'uploads/customer_images/' . $imageName;
        }

        $otp = random_int(100000, 999999);
        $tempUserData['otp'] = $otp;

        // --- ADDED: Store existing customer ID in session ---
        $tempUserData['existing_customer_id'] = $existingCustomer ? $existingCustomer->id : null;

        session(['temp_user_data' => $tempUserData]);

       // dd($request->phone);
        
        if ($this->sendSmsOtp($request->phone, $otp)) {
            return response()->json(['success' => true, 'message' => 'A 6-digit OTP has been sent to your phone number.']);
        } else {
            return response()->json(['success' => false, 'message' => 'Could not send OTP. Please check your phone number and try again.'], 500);
        }
    }

    /**
     * Verify the OTP and create the user.
     */
    public function verifyOtp(Request $request)
{
    $validator = Validator::make($request->all(), [
        'otp' => 'required|numeric|digits:6',
    ]);

    if ($validator->fails()) {
        return response()->json(['success' => false, 'message' => 'Please enter a valid 6-digit OTP.'], 422);
    }

    $tempUserData = session('temp_user_data');
    if (!$tempUserData || $tempUserData['otp'] != $request->otp) {
        return response()->json(['success' => false, 'message' => 'The provided OTP is invalid.'], 400);
    }

    // --- MODIFIED CREATION/UPDATE LOGIC ---
    $existingCustomerId = $tempUserData['existing_customer_id'] ?? null;
    $user = null;

    DB::beginTransaction();
    try {
        if ($existingCustomerId) {
            // --- SCENARIO 1: UPDATE EXISTING CUSTOMER, CREATE NEW USER ---

            // 1. Create the User
            $user = User::create([
                'name' => $tempUserData['name'],
                'email' => $tempUserData['email'],
                'phone' => $tempUserData['phone'],
                'password' => Hash::make($tempUserData['password']),
                'viewpassword' => $tempUserData['password'],
                'email_verified_at' => now(),
                'user_type' => 1,
                'status' => 1,
            ]);

            // 2. Find and Update the Customer
            $customer = Customer::findOrFail($existingCustomerId);
            $customer->update([
                'name' => $tempUserData['name'],
                'email' => $tempUserData['email'],
                'password' => $tempUserData['password'], // Setter in Customer model will hash
                'user_id' => $user->id,
                'slug' => Str::slug($tempUserData['name']).'-'.uniqid(),
                'source' => 'website',
                'status' => 1,
            ]);

            // 3. Link User back to Customer
            $user->customer_id = $customer->id;
            $user->save();

        } else {
            // --- SCENARIO 2: CREATE NEW USER AND NEW CUSTOMER (Original Logic) ---

            // 1. Create User
            $user = User::create([
                'name' => $tempUserData['name'],
                'email' => $tempUserData['email'],
                'phone' => $tempUserData['phone'],
                'password' => Hash::make($tempUserData['password']),
                'viewpassword' => $tempUserData['password'],
                'email_verified_at' => now(),
                'user_type' => 1,
                'status' => 1,
            ]);

            // 2. Create Customer
            $customer = Customer::create([
                'name' => $tempUserData['name'],
                'email' => $tempUserData['email'],
                'phone' => $tempUserData['phone'],
                'status' => 1,
                'type' => 'normal',
                'source' => 'website',
                'password' => $tempUserData['password'], // Setter will hash
                'slug' => Str::slug($tempUserData['name']).'-'.uniqid(),
                'user_id' => $user->id,
            ]);

            // 3. Link User to Customer
            $user->customer_id = $customer->id;
            $user->save();
        }

        DB::commit();

        // Continue to login
        session()->forget('temp_user_data');
        Auth::login($user);
        return response()->json(['success' => true, 'redirect_url' => route('dashboard.user')]);

    } catch (Exception $e) {
        DB::rollBack();
        \Log::error('Registration Error: ' . $e->getMessage(), ['data' => $tempUserData]);
        return response()->json(['success' => false, 'message' => 'An error occurred during registration. Please try again.'], 500);
    }
    // --- END MODIFIED LOGIC ---
}
    
    /**
     * Resend the OTP for registration.
     */
    public function resendOtp()
    {
        $tempUserData = session('temp_user_data');

        if (!$tempUserData || !isset($tempUserData['phone'])) {
            return response()->json(['success' => false, 'message' => 'Your session has expired. Please register again.'], 422);
        }

        $otp = random_int(100000, 999999);
        $tempUserData['otp'] = $otp;
        session(['temp_user_data' => $tempUserData]); // Resave session with new OTP

        // --- UPDATED: Resend OTP via SMS ---
        if ($this->sendSmsOtp($tempUserData['phone'], $otp)) {
            return response()->json(['success' => true, 'message' => 'A new OTP has been sent to your phone number.']);
        } else {
            return response()->json(['success' => false, 'message' => 'We could not resend the OTP. Please try again later.'], 500);
        }
    }

    /**
     * Handle a logout request using the default auth guard.
     */
    public function logout(Request $request)
    {
        Auth::logout();
        $request->session()->invalidate();
        $request->session()->regenerateToken();
        return redirect('/');
    }

    /**
     * Show the user's dashboard.
     */
    public function dashboarduser()
    {
        // Get the authenticated User model instance
        $user = Auth::user();
//dd($user->id);
        if (!$user) {
            return redirect()->route('home.index');
        }

        // Get the associated Customer model through the relationship
        $customer = $user->customer;

        if (!$customer) {
             // Handle cases where a user might exist without a customer profile
            return redirect()->route('home.index')->with('error', 'Customer profile not found.');
        }

        Cookie::queue('user_phone_for_login', $user->phone, 120);

        $customer->load([
            'orders' => function ($query) {
                $query->withCount('orderDetails')->latest();
            },
            'addresses'
        ]);

        $recentOrders = $customer->orders->where('status', '!=', 'cancel')->take(10);
        $cancelOrders = $customer->orders->where('status', 'cancel')->take(10);

        $billingAddress = $customer->addresses->where('address_type', 'billing')->where('is_default', 1)->first()
            ?? $customer->addresses->where('address_type', 'billing')->first();

        $shippingAddress = $customer->addresses->where('address_type', 'shipping')->where('is_default', 1)->first()
            ?? $customer->addresses->where('address_type', 'shipping')->first();

        // Pass the customer data to the view, aliased as 'user' for consistency
        return view('front.dashboarduser', [
            'user' => $customer, 
            'recentOrders' => $recentOrders, 
            'cancelOrders' => $cancelOrders, 
            'billingAddress' => $billingAddress, 
            'shippingAddress' => $shippingAddress
        ]);
    }


    // ====================================================================
    // --- NEW PASSWORD RESET (PHONE OTP) METHODS ---
    // ====================================================================

    /**
     * Send a password reset OTP to the user's phone.
     */
    public function sendPasswordResetOtp(Request $request)
    {
        // Prepend '0' to the 10-digit phone number
        if ($request->has('phone')) {
            $request->merge([
                'phone' => '0' . $request->phone
            ]);
        }
        $formattedPhone = $request->phone;

        $validator = Validator::make($request->all(), [
            'phone' => 'required|string|digits:11|exists:users,phone',
        ], [
            'phone.exists' => 'No account found with this phone number.'
        ]);

        if ($validator->fails()) {
            return response()->json(['success' => false, 'errors' => $validator->errors()], 422);
        }

        $otp = random_int(100000, 999999);

        // Store reset data in a separate session key to avoid conflict with registration
        session(['password_reset_data' => [
            'phone' => $formattedPhone,
            'otp'   => $otp,
        ]]);

        if ($this->sendSmsOtp($formattedPhone, $otp)) {
            return response()->json(['success' => true, 'message' => 'An OTP has been sent to your phone number.']);
        } else {
            return response()->json(['success' => false, 'message' => 'Could not send OTP. Please try again.'], 500);
        }
    }

    /**
     * Verify the password reset OTP.
     */
    public function verifyPasswordResetOtp(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'otp' => 'required|numeric|digits:6',
        ]);

        if ($validator->fails()) {
            return response()->json(['success' => false, 'message' => 'Please enter a valid 6-digit OTP.'], 422);
        }

        $resetData = session('password_reset_data');
        if (!$resetData || $resetData['otp'] != $request->otp) {
            return response()->json(['success' => false, 'message' => 'The provided OTP is invalid.'], 400);
        }

        // OTP is correct. Store the verified phone in the session for the final step
        // and clear the OTP data.
        session(['password_reset_verified_phone' => $resetData['phone']]);
        session()->forget('password_reset_data');

        return response()->json(['success' => true]);
    }

    /**
     * Resend the password reset OTP.
     */
    public function resendPasswordResetOtp()
    {
        $resetData = session('password_reset_data');

        if (!$resetData || !isset($resetData['phone'])) {
            return response()->json(['success' => false, 'message' => 'Your session has expired. Please try again.'], 422);
        }

        $otp = random_int(100000, 999999);
        $resetData['otp'] = $otp;
        session(['password_reset_data' => $resetData]); // Resave session with new OTP

        if ($this->sendSmsOtp($resetData['phone'], $otp)) {
            return response()->json(['success' => true, 'message' => 'A new OTP has been sent.']);
        } else {
            return response()->json(['success' => false, 'message' => 'Could not resend OTP.'], 500);
        }
    }


    /**
     * Update the password after successful OTP verification.
     */
    public function updatePasswordFromOtp(Request $request)
    {
        // Check if the user has been verified via
        $phone = session('password_reset_verified_phone');
        if (!$phone) {
            return response()->json(['success' => false, 'message' => 'Your verification session has expired. Please try again.'], 403);
        }

        $validator = Validator::make($request->all(), [
            'password' => 'required|string|min:8|confirmed',
        ]);

        if ($validator->fails()) {
            return response()->json(['success' => false, 'errors' => $validator->errors()], 422);
        }

        $user = User::where('phone', $phone)->first();
        if (!$user) {
            // This should not happen if session is secure, but as a safeguard.
            return response()->json(['success' => false, 'message' => 'User not found.'], 404);
        }

        $user->password = Hash::make($request->password);
        $user->viewpassword = $request->password;
        $user->save();
        
        // Also update the customer record if it exists
        if ($user->customer) {
            $user->customer->password = $request->password; // Uses setter in Customer model
            $user->customer->save();
        }

        // Clear the verification session
        session()->forget('password_reset_verified_phone');

        // Log the user in
        Auth::login($user);

        return response()->json(['success' => true, 'redirect_url' => route('dashboard.user')]);
    }

    // --- END NEW PASSWORD RESET METHODS ---


    /**
     * Update basic user profile information (Name, Gender, DOB).
     */
    public function updateProfileInfo(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'name' => 'required|string|max:255',
             'secondary_phone' => 'nullable|string|digits:11',
            // Add validation for gender and dob if you have them in the db
        ]);

        if ($validator->fails()) {
            return response()->json(['success' => false, 'message' => $validator->errors()->first()], 422);
        }

        $user = Auth::user();
        $user->name = $request->name;
        $user->gender = $request->gender;
        $user->dob = $request->dob;
         $user->secondary_phone = $request->secondary_phone;
        $user->save();

        if ($user->customer) {
            $user->customer->name = $request->name;
            $user->customer->secondary_phone = $request->secondary_phone;
            $user->customer->save();
        }

        return response()->json(['success' => true, 'message' => 'Profile updated successfully!', 'newName' => $user->name]);
    }

    /**
     * Send an OTP to verify a new email or phone number before updating.
     */
    public function sendUpdateVerificationOtp(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'field' => 'required|string|in:email,phone',
            'value' => 'required|string',
        ]);

        if ($validator->fails()) {
            return response()->json(['success' => false, 'message' => $validator->errors()->first()], 422);
        }
        
        $field = $request->field;
        $value = $request->value;

        // Additional validation to check for uniqueness
        if ($field === 'email') {
            if (!filter_var($value, FILTER_VALIDATE_EMAIL)) {
                 return response()->json(['success' => false, 'message' => 'The email must be a valid email address.'], 422);
            }
            if (User::where('email', $value)->where('id', '!=', Auth::id())->exists()) {
                return response()->json(['success' => false, 'message' => 'This email is already taken.'], 422);
            }
        }
        if ($field === 'phone') {
             if (User::where('phone', $value)->where('id', '!=', Auth::id())->exists()) {
                return response()->json(['success' => false, 'message' => 'This phone number is already taken.'], 422);
            }
        }

        $otp = random_int(100000, 999999);
        
        $verificationData = [
            'field' => $field,
            'value' => $value,
            'otp' => $otp,
        ];
        
        session(['update_verification_data' => $verificationData]);

          if ($field === 'email') {
            try {
                Mail::send('front.emails.otp_email', ['otp' => $otp, 'name' => Auth::user()->name], function ($message) use ($value) {
                    $message->to($value);
                    $message->subject('Verify Your Information Update');
                });
                return response()->json(['success' => true, 'message' => 'An OTP has been sent to ' . $value]);
            } catch (Exception $e) {
                \Log::error("Update OTP email sending failed: " . $e->getMessage());
                return response()->json(['success' => false, 'message' => 'Could not send OTP email. Please try again.'], 500);
            }
        } elseif ($field === 'phone') {
            if ($this->sendSmsOtp($value, $otp)) {
                return response()->json(['success' => true, 'message' => 'An OTP has been sent to ' . $value]);
            } else {
                return response()->json(['success' => false, 'message' => 'Could not send OTP SMS. Please try again.'], 500);
            }
        }
    }

    /**
     * Verify the OTP and update the user's field (email or phone).
     */
    public function verifyAndUpdateField(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'otp' => 'required|numeric|digits:6',
        ]);
        
        if ($validator->fails()) {
            return response()->json(['success' => false, 'message' => 'Please enter a valid 6-digit OTP.'], 422);
        }

        $verificationData = session('update_verification_data');
        if (!$verificationData || $verificationData['otp'] != $request->otp) {
            return response()->json(['success' => false, 'message' => 'The provided OTP is invalid.'], 400);
        }
        
        $user = Auth::user();
        $field = $verificationData['field'];
        $value = $verificationData['value'];

        $user->{$field} = $value;
        if ($field === 'email') {
            $user->email_verified_at = now(); // Mark new email as verified
        }
        $user->save();

        if ($user->customer) {
            $user->customer->{$field} = $value;
            $user->customer->save();
        }

        session()->forget('update_verification_data');

        return response()->json(['success' => true, 'message' => ucfirst($field) . ' has been updated successfully.']);
    }


     public function userOrderList()
    {
        $user = Auth::user();

        if (!$user || !$user->customer) {
            return redirect()->route('home.index');
        }

        $customer = $user->customer;

        // Fetch all orders with their details and group them by status for the tabs
        $orders = $customer->orders()->with('orderDetails.product')->latest()->get();

        $ordersByStatus = $orders->groupBy('status');

        // Pass the customer data aliased as 'user' for consistency with the sidebar
        $user = $customer;

        // Note: This now points to a different main view that will include the order list
        return view('front.dashboard.user_orders', compact('user', 'ordersByStatus'));
    }

    public function updateProfileAddress()
    {
        $user = Auth::user();
        if (!$user || !$user->customer) {
            return redirect()->route('home.index');
        }
        $customer = $user->customer;
        $customer->load('addresses');
        return view('front.dashboard.user_address', ['user' => $customer]);
    }


    // --- NEW ADDRESS MANAGEMENT METHODS ---

    public function storeAddress(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'district' => 'required|string',
            'upazila' => 'required|string',
            'address' => 'required|string|max:255',
            'address_type' => 'required|string|in:Home,Office,Others',
            'is_default' => 'nullable|boolean',
        ]);

        if ($validator->fails()) {
            return response()->json(['success' => false, 'errors' => $validator->errors()], 422);
        }

        $customer = Auth::user()->customer;
        $fullAddress = $request->address . ', ' . $request->upazila . ', ' . $request->district;

        if ($request->is_default) {
            // Set other addresses of the same type to not be default
            $customer->addresses()->where('address_type', $request->address_type)->update(['is_default' => 0]);
        }

        $address = $customer->addresses()->create([
            'address' => $fullAddress,
            'address_type' => $request->address_type,
            'is_default' => $request->is_default ? 1 : 0,
        ]);
        
        // Return a representation of the newly created address card
        $user = $customer; // for the partial view
        $newAddressHtml = view('front.dashboard.partials._address_card', compact('address', 'user'))->render();


        return response()->json([
            'success' => true, 
            'message' => 'Address added successfully!',
            'newAddressHtml' => $newAddressHtml
        ]);
    }

    public function updateAddress(Request $request)
    {
         $validator = Validator::make($request->all(), [
            'address_id' => 'required|integer|exists:customer_addresses,id',
            'district' => 'required|string',
            'upazila' => 'required|string',
            'address' => 'required|string|max:255',
            'address_type' => 'required|string|in:Home,Office,Others',
            'is_default' => 'nullable|boolean',
        ]);

        if ($validator->fails()) {
            return response()->json(['success' => false, 'errors' => $validator->errors()], 422);
        }
        
        $customer = Auth::user()->customer;
        $address = $customer->addresses()->findOrFail($request->address_id);

        if ($request->is_default) {
            $customer->addresses()->where('address_type', $request->address_type)->update(['is_default' => 0]);
        }

        $fullAddress = $request->address . ', ' . $request->upazila . ', ' . $request->district;
        
        $address->update([
            'address' => $fullAddress,
            'address_type' => $request->address_type,
            'is_default' => $request->is_default ? 1 : 0,
        ]);
        
        $user = $customer;
        $updatedAddressHtml = view('front.dashboard.partials._address_card', compact('address', 'user'))->render();

        return response()->json([
            'success' => true, 
            'message' => 'Address updated successfully!',
            'addressId' => $address->id,
            'updatedAddressHtml' => $updatedAddressHtml
        ]);
    }

    public function destroyAddress(Request $request)
    {
        $request->validate(['address_id' => 'required|integer|exists:customer_addresses,id']);
        $customer = Auth::user()->customer;
        $address = $customer->addresses()->findOrFail($request->address_id);
        
        // Prevent deletion of the last default address if you want to enforce at least one default
        if ($address->is_default) {
            $otherDefaults = $customer->addresses()
                                    ->where('address_type', $address->address_type)
                                    ->where('id', '!=', $address->id)
                                    ->where('is_default', 1)
                                    ->exists();
            if (!$otherDefaults) {
                 // Optionally, you could set another address as default before deleting
                 // For now, let's just prevent it if it's the sole default of its type.
                 // This logic can be adjusted based on business rules.
            }
        }

        $address->delete();
        return response()->json(['success' => true, 'message' => 'Address deleted successfully!']);
    }

    public function setDefaultAddress(Request $request)
    {
        $request->validate(['address_id' => 'required|integer|exists:customer_addresses,id']);
        $customer = Auth::user()->customer;
        $address = $customer->addresses()->findOrFail($request->address_id);
        
        // Unset other defaults of the same type
        $customer->addresses()->where('address_type', '!=', $address->address_type)->update(['is_default' => 0]);
        
        // Set the new default
        $address->update(['is_default' => 1]);
        
        // We need to return all address cards to update their default status indicators
        $customer->load('addresses');
        $user = $customer;
        $allAddressesHtml = '';
        foreach($customer->addresses as $addr) {
            $allAddressesHtml .= view('front.dashboard.partials._address_card', ['address' => $addr, 'user' => $user])->render();
        }

        return response()->json([
            'success' => true, 
            'message' => 'Default address updated!',
            'allAddressesHtml' => $allAddressesHtml
        ]);
    }


   public function userOrderDetail($id)
    {
        $decodedId = base64_decode($id);
        $user = Auth::user();

        if (!$user || !$user->customer) {
            return redirect()->route('home.index');
        }

        $customer = $user->customer;
        $order = $customer->orders()
                          ->with(['orderDetails.product', 'trackingHistory'])
                          ->where('id', $decodedId)
                          ->firstOrFail();

        return view('front.dashboard.user_order_detail', ['user' => $customer, 'order' => $order]);
    }

     public function cancelOrder(Request $request)
    {
        $request->validate(['order_id' => 'required|integer']);
        $order = Auth::user()->customer->orders()->where('id', $request->order_id)->firstOrFail();
        if ($order->status !== 'pending') {
            return response()->json(['success' => false, 'message' => 'This order can no longer be cancelled.'], 403);
        }
        try {
            DB::beginTransaction();
            $order->status = 'Cancelled';
            $order->save();
            OrderTracking::create(['order_id' => $order->id, 'invoice_no' => $order->invoice_no, 'status' => 'Cancelled']);
            DB::commit();
            return response()->json(['success' => true, 'message' => 'Your order has been cancelled successfully.']);
        } catch (Exception $e) {
            DB::rollBack();
            \Log::error("Order cancellation failed: " . $e->getMessage());
            return response()->json(['success' => false, 'message' => 'Could not cancel the order. Please try again.'], 500);
        }
    }

     public function downloadInvoice($id)
    {
        $decodedId = base64_decode($id);
        $user = Auth::user();

        if (!$user || !$user->customer) {
            abort(404);
        }

        $customer = $user->customer;
        $order = $customer->orders()
                          ->with(['orderDetails.product'])
                          ->where('id', $decodedId)
                          ->firstOrFail();

        // Setup mPDF
        $mpdf = new Mpdf([
            'mode' => 'utf-8',
            'format' => 'A4',
            'margin_header' => 10,
            'margin_footer' => 10,
            'orientation' => 'P'
        ]);

        // Render the invoice view to HTML
        $html = view('front.dashboard.invoice', compact('order'))->render();

        // Write HTML to PDF
        $mpdf->WriteHTML($html);

        // Output the PDF for download
        $fileName = 'invoice-' . $order->invoice_no . '.pdf';
        return $mpdf->Output($fileName, 'I'); // 'D' forces a download
    }

     public function reorder(Request $request)
    {
        $request->validate(['order_id' => 'required|integer']);
        $customer = Auth::user()->customer;
        $order = $customer->orders()->with('orderDetails.product.variants.color')->findOrFail($request->order_id);
        $cart = Session::get('cart', []);

        foreach ($order->orderDetails as $detail) {
            $product = $detail->product;
            $variant = $product ? $product->variants->find($detail->product_variant_id) : null;
            if (!$product || !$variant) { continue; }
            $cartItemId = $variant->id . '-' . str_replace(' ', '', $detail->size);
            $basePrice = $product->discount_price ?? $product->base_price;
            $finalPrice = $basePrice + ($variant->additional_price ?? 0);
            $image = $variant->variant_image[0] ?? $product->thumbnail_image[0] ?? null;

            if (isset($cart[$cartItemId])) {
                $cart[$cartItemId]['quantity'] += $detail->quantity;
            } else {
                $cart[$cartItemId] = [ 'rowId' => $cartItemId, 'product_id' => $product->id, 'variant_id' => $variant->id, 'name' => $product->name, 'size' => $detail->size, 'color' => $variant->color->name ?? 'N/A', 'quantity' => $detail->quantity, 'price' => $finalPrice, 'image' => $image, 'slug' => $product->slug, 'is_bundle' => false, 'url' => route('product.show', $product->slug)];
            }
        }
        Session::put('cart', $cart);
        return response()->json(['success' => true, 'message' => 'Items added to your cart!', 'redirect_url' => route('cart.show')]);
    }

}