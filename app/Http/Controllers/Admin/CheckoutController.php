<?php

namespace App\Http\Controllers\Admin;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Session;
use Illuminate\Support\Facades\Validator;
use Illuminate\Support\Facades\DB;
use App\Models\RedexArea;
use App\Models\Order;
use App\Models\Product;
use App\Models\OrderDetail;
use App\Models\BundleOfferProduct;
use Exception;
use App\Library\SslCommerz\SslCommerzNotification;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Cookie; // ADDED: For handling cookies
use App\Models\User;
class CheckoutController extends Controller
{

     private $base_url;
    private $app_key;
    private $app_secret;
    private $username;
    private $password;


    public function __construct()
    {
        // Sandbox
        $this->base_url = 'https://tokenized.sandbox.bka.sh/v1.2.0-beta';
        // Live
    $this->base_url = 'https://tokenized.pay.bka.sh/v1.2.0-beta'; 
$BKASH_CHECKOUT_URL_USER_NAME ='01965665880';
$BKASH_CHECKOUT_URL_PASSWORD = 'iRI:SK7tWbz';
$BKASH_CHECKOUT_URL_APP_KEY = 'JTKshr429pkbVxT6sJYjUrDPtc';
$BKASH_CHECKOUT_URL_APP_SECRET ='cdjFKfCvfzZxReRTogc60eASv9ZnNDZrtu3K5GzXCUunTyW1CxYz';

//sandbox
// $BKASH_CHECKOUT_URL_USER_NAME ='sandboxTokenizedUser02';
// $BKASH_CHECKOUT_URL_PASSWORD = 'sandboxTokenizedUser02@12345';
// $BKASH_CHECKOUT_URL_APP_KEY = '4f6o0cjiki2rfm34kfdadl1eqq';
// $BKASH_CHECKOUT_URL_APP_SECRET ='2is7hdktrekvrbljjh44ll3d9l1dtjo4pasmjvs5vl5qr3fug4b';


        $this->app_key = $BKASH_CHECKOUT_URL_APP_KEY;
        $this->app_secret = $BKASH_CHECKOUT_URL_APP_SECRET;
        $this->username = $BKASH_CHECKOUT_URL_USER_NAME;
        $this->password = $BKASH_CHECKOUT_URL_PASSWORD;
        
        
    }

    // BKASH HELPER: Get bKash auth token
  // BKASH HELPER: Get bKash auth token
    private function bkashGetToken()
    {
        $url = $this->base_url . '/tokenized/checkout/token/grant';

        $response = Http::withHeaders([
            'Content-Type' => 'application/json',
            'username'     => $this->username,
            'password'     => $this->password,
        ])->post($url, [
            'app_key'    => $this->app_key,
            'app_secret' => $this->app_secret,
        ]);

        // Check if the request was successful and the token exists
        if ($response->successful() && $response->json('id_token')) {
            return $response->json('id_token');
        }

        // Optional: Log the error for debugging
        \Log::error('bKash Token Error: ' . $response->body());
        return null;
    }

    // BKASH HELPER: Make an API call to bKash
    // BKASH HELPER: Make an API call to bKash
    private function bkashApiCall($url, $post_data, $token)
    {
        $response = Http::withHeaders([
            'Content-Type'  => 'application/json',
            'Authorization' => $token,
            'X-App-Key'     => $this->app_key,
        ])->post($url, $post_data);

        // Return the JSON response as an array
        return $response->json();
    }
    private function getCartData()
{
    $cart = Session::get('cart', []);
    $subtotal = 0;
    foreach ($cart as $item) {
        $subtotal += $item['price'] * $item['quantity'];
    }

    $coupon = Session::get('coupon');
    $discount = 0;
    
    if ($coupon) {
        $eligibleSubtotal = 0;
        $productIdsInCart = collect($cart)->where('is_bundle', false)->pluck('product_id')->unique()->all();
        
        if(!empty($productIdsInCart)){
            $products = Product::whereIn('id', $productIdsInCart)->get()->keyBy('id');
            foreach ($cart as $item) {
                // Skip bundles or items whose product details couldn't be fetched
                if (isset($item['is_bundle']) && $item['is_bundle']) continue;
                if (!isset($products[$item['product_id']])) continue;

                $product = $products[$item['product_id']];

                // --- CORE CHANGE: Skip products that are already on discount ---
                if (isset($product->discount_price) && $product->discount_price > 0) {
                    continue;
                }

                $isCouponForAll = empty($coupon->product_ids) && empty($coupon->category_ids);
                $isProductEligible = !empty($coupon->product_ids) && in_array($product->id, $coupon->product_ids);
                $isCategoryEligible = !empty($coupon->category_ids) && in_array($product->category_id, $coupon->category_ids);
                
                if ($isCouponForAll || $isProductEligible || $isCategoryEligible) {
                    $eligibleSubtotal += $item['price'] * $item['quantity'];
                }
            }
        }
        
        if ($coupon->type === 'fixed') {
            $discount = $coupon->value;
        } elseif ($coupon->type === 'percent') {
            $discount = ($eligibleSubtotal * $coupon->value) / 100;
        }
        
        $discount = min($discount, $eligibleSubtotal);
    }
    
    return [
        'cart'       => $cart,
        'subtotal'   => $subtotal,
        'discount'   => $discount,
        'coupon'     => $coupon,
    ];
}

    public function checkout()
    {
        $cartData = $this->getCartData();

        if (count($cartData['cart']) == 0) {
            return redirect()->route('cart.show')->with('error', 'Your cart is empty.');
        }

        $customer = Auth::user()->customer->load('addresses');

        return view('front.checkout.checkout', [
            'cartItems' => $cartData['cart'],
            'subtotal'  => $cartData['subtotal'],
            'discount'  => $cartData['discount'],
            'coupon'    => $cartData['coupon'],
            'addresses' => $customer->addresses,
        ]);
    }

    public function getShippingCharge(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'address_id' => 'required|exists:customer_addresses,id'
        ]);

        if ($validator->fails()) {
            return response()->json(['success' => false, 'message' => 'Please select a valid address.'], 422);
        }

        // --- START: NEW FREE SHIPPING LOGIC ---
        $cart = Session::get('cart', []);
        $productIds = [];
        $bundleOfferProductIds = []; // This will hold the BundleOfferProduct IDs from the cart

        foreach ($cart as $item) {
            if (isset($item['is_bundle']) && $item['is_bundle']) {
                // 'id' in a bundle item is the BundleOfferProduct ID
                $bundleOfferProductIds[] = $item['id']; 
            } else {
                $productIds[] = $item['product_id'];
            }
        }

        // Check 1: Do any of the regular products have free delivery?
        if (count($productIds) > 0) {
            $hasFreeShippingProduct = Product::whereIn('id', $productIds)
                                              ->where('is_free_delivery', true)
                                              ->exists();
            if ($hasFreeShippingProduct) {
                // Found a free shipping product, so the charge is 0.
                return response()->json(['success' => true, 'shipping_charge' => 0]);
            }
        }
        
        // Check 2: Do any of the bundles have free delivery?
        if (count($bundleOfferProductIds) > 0) {
            // We check if any BundleOfferProduct in the cart belongs to a BundleOffer that has free delivery.
            $hasFreeShippingBundle = BundleOfferProduct::whereIn('id', $bundleOfferProductIds)
                ->whereHas('bundleOffer', function ($query) {
                    $query->where('is_free_delivery', true);
                })
                ->exists();

            if ($hasFreeShippingBundle) {
                // Found a free shipping bundle, so the charge is 0.
                return response()->json(['success' => true, 'shipping_charge' => 0]);
            }
        }
        // --- END: NEW FREE SHIPPING LOGIC ---

        // If we're still here, no free shipping was found. Proceed with normal calculation.
        $customer = Auth::user()->customer;
        $address = $customer->addresses()->findOrFail($request->address_id);
        
        $addressParts = explode(',', $address->address);
        
        if (count($addressParts) < 3) {
            return response()->json(['success' => false, 'message' => 'Address format is incorrect. Please edit the address.'], 400);
        }

        $upazila = trim($addressParts[count($addressParts) - 2]);
        $district = trim($addressParts[count($addressParts) - 1]);

        $area = RedexArea::where('District', $district)->where('Upazila_Thana', $upazila)->first();

        $shippingCharge = $area ? $area->Delivery_Charge : 70; // Default if not found

        return response()->json([
            'success' => true,
            'shipping_charge' => $shippingCharge
        ]);
    }
    
     public function placeOrder(Request $request)
    {
        // Use request->validate() which handles redirects automatically on failure
        $request->validate([
            'shipping_address_id' => 'required|exists:customer_addresses,id',
            'payment_method'      => 'required|string|in:cod,sslcommerz,bkash',
            'delivery_type'       => 'required|string|in:regular,express',
            'notes'               => 'nullable|string',
            'shipping_cost'       => 'required|numeric|min:0',
        ]);

        $cartData = $this->getCartData();
        if (count($cartData['cart']) == 0) {
            return redirect()->route('cart.show')->with('error', 'Your cart is empty.');
        }

       

        $user = Auth::user();
        $customer = $user->customer;
        $shippingAddress = $customer->addresses()->findOrFail($request->shipping_address_id);

         // ADDED: Store user's phone in a temporary cookie (10 minutes)
        // This cookie will be used to log them back in after payment.
        //dd($user->phone);
            
        
        //dd(Cookie::get('user_phone_for_login'));
        $totalAmount = ($cartData['subtotal'] - $cartData['discount']) + $request->shipping_cost;

        DB::beginTransaction();
        try {

             do {
                $invoiceNumber = rand(1000, 9999);
            } while (Order::where('invoice_no', $invoiceNumber)->exists());


            $order = Order::create([
                'customer_id'      => $customer->id,
                'invoice_no'       => $invoiceNumber,
                'subtotal'         => $cartData['subtotal'],
                'shipping_cost'    => $request->shipping_cost,
                'discount'         => $cartData['discount'],
                'total_amount'     => $totalAmount,
                'status'           => 'pending',
                'shipping_address' => $shippingAddress->address . ', ' . $shippingAddress->phone,
                'billing_address'  => $shippingAddress->address . ', ' . $shippingAddress->phone,
                'payment_method'   => $request->payment_method,
                'delivery_type'    => $request->delivery_type,
                'payment_term'     => $request->payment_method == 'cod' ? 'cod' : 'online_payment',
                'total_pay'        => 0,
                'cod'              => $request->payment_method == 'cod' ? $totalAmount : 0,
                'due'              => $totalAmount,
                'order_from'       => 'web',
                   'currency'         => 'BDT',
                'payment_status'   => 'unpaid',
                'notes'            => $request->notes,
            ]);

            foreach ($cartData['cart'] as $item) {
                 if (isset($item['is_bundle']) && $item['is_bundle']) {
                    foreach ($item['selected_products'] as $bundleProduct) {
                        OrderDetail::create([
                            'order_id' => $order->id, 'product_id' => $bundleProduct['product_id'], 'product_variant_id' => $bundleProduct['variant_id'],
                            'color' => $bundleProduct['color'], 'size' => $bundleProduct['size'], 'quantity' => $item['quantity'],
                            'unit_price' => $bundleProduct['price'], 'subtotal' => $bundleProduct['price'] * $item['quantity'],
                        ]);
                    }
                } else {
                    OrderDetail::create([
                        'order_id' => $order->id, 'product_id' => $item['product_id'], 'product_variant_id' => $item['variant_id'],
                        'color' => $item['color'], 'size' => $item['size'], 'quantity' => $item['quantity'],
                        'unit_price' => $item['price'], 'subtotal' => $item['price'] * $item['quantity'],
                    ]);
                }
            }
            
            DB::commit();

            // --- Payment Gateway Logic ---
            if ($request->payment_method == 'sslcommerz') {
                $post_data = array();
                $post_data['total_amount'] = $order->total_amount;
                $post_data['currency'] = "BDT";
                $post_data['tran_id'] = $order->invoice_no;

                $post_data['cus_name'] = $user->name;
                $post_data['cus_email'] = $user->email ?? 'customer@example.com';
                $post_data['cus_add1'] = $shippingAddress->address;
                $post_data['cus_city'] = "Dhaka";
                $post_data['cus_state'] = "Dhaka";
                $post_data['cus_postcode'] = "1200";
                $post_data['cus_country'] = "Bangladesh";
                $post_data['cus_phone'] = $user->phone;
                
                $post_data['shipping_method'] = "NO";
                $post_data['product_name'] = "E-commerce Product";
                $post_data['product_category'] = "General";
                $post_data['product_profile'] = "general";

                $sslc = new SslCommerzNotification();
                $payment_options = $sslc->makePayment($post_data, 'hosted');

                if (is_array($payment_options) && array_key_exists('GatewayPageURL', $payment_options)) {
                    // Redirect the user to the payment gateway
                    return redirect($payment_options['GatewayPageURL']);
                } else {
                    DB::rollBack();
                    return redirect()->back()->with('error', 'Payment gateway failed. Please try again.');
                }

            } else if ($request->payment_method == 'bkash') {
              $token = $this->bkashGetToken();
                if (!$token) {
                    return redirect()->back()->with('error', 'bKash token generation failed. Please try again.');
                }

                $request_data = [
                    'mode' => '0011',
                    'payerReference' => ' ',
                    'callbackURL' => route('bkash.callback'),
                    'amount' => $order->total_amount, // For testing, use 10. Change to $order->total_amount in production
                    'currency' => 'BDT',
                    'intent' => 'sale',
                    'merchantInvoiceNumber' => $order->invoice_no,
                ];

                $url = $this->base_url . '/tokenized/checkout/create';
                $response = $this->bkashApiCall($url, $request_data, $token);

                if (isset($response['bkashURL'])) {
                    // Store the paymentID to verify in the callback
                    $order->trxID = $response['paymentID'];
                    $order->save();
                    return redirect($response['bkashURL']);
                }
                
                return redirect()->back()->with('error', $response['statusMessage'] ?? 'bKash payment creation failed.');
            } else { // COD
                Session::forget('cart');
                Session::forget('coupon');
                // Redirect to the order success page
                return redirect()->route('order.success', ['orderId' => $order->id])->with('success', 'Your order has been placed successfully!');
            }

        } catch (Exception $e) {
            DB::rollBack();
            \Log::error('Order placement failed: ' . $e->getMessage());
            return redirect()->back()->with('error', 'Could not place order. Please try again.');
        }
    }
    
  
    // NEW BKASH CALLBACK METHOD
    public function bkashCallback(Request $request)
    {
        if ($request->status != 'success' || !$request->paymentID) {
            return redirect()->route('cart.show')->with('error', 'bKash payment was cancelled or failed.');
        }

        $paymentID = $request->paymentID;
        $order = Order::where('trxID', $paymentID)->where('payment_status', 'unpaid')->first();

        if (!$order) {
            return redirect()->route('cart.show')->with('error', 'Invalid bKash payment ID or order already processed.');
        }

        $token = $this->bkashGetToken();
        if (!$token) {
            return redirect()->route('cart.show')->with('error', 'bKash token generation failed while executing payment.');
        }

        $request_data = ['paymentID' => $paymentID];
        $url = $this->base_url . '/tokenized/checkout/execute';
        $response = $this->bkashApiCall($url, $request_data, $token);

        if (isset($response['statusCode']) && $response['statusCode'] == '0000') {
            // Verify amount
            if ($response['amount'] != $order->total_amount) { // For testing, use 10. Change to $order->total_amount in production
                // You should handle this case by refunding the payment via bKash API and marking the order as failed.
                \Log::error('bKash amount mismatch for order: '.$order->id);
                return redirect()->route('cart.show')->with('error', 'Payment amount mismatch. Please contact support.');
            }

            // Update order status
            $order->update([
                'status' => 'pending',
                'payment_status' => 'paid',
                'trxID' => $response['trxID'], // Store the final transaction ID
                'total_pay' => $response['amount'],
                'due' => 0,
                'cod' => 0,
                'statusMessage' => $response['statusMessage']
            ]);

            Session::forget('cart');
            Session::forget('coupon');

            return redirect()->route('order.success', ['orderId' => $order->id])->with('success', 'Payment successful!');
        }
        
        return redirect()->route('cart.show')->with('error', $response['statusMessage'] ?? 'bKash payment execution failed.');
    }


    public function orderSuccess($orderId)
    {


      
           // Retrieve the cookie value from the request
    $phone = Cookie::get('user_phone_for_login');

    if ($phone) {
        // Now you can use the phone number
        // For example: find the user and log them in
        $user = User::where('phone', $phone)->first();
        if ($user) {
            Auth::login($user);
        }
    }

            // Delete the cookie immediately after use for security
            Cookie::queue(Cookie::forget('user_phone_for_login'));
        
        $order = Order::with('customer', 'orderDetails.product')
                      ->where('id', $orderId)
                      ->where('customer_id', Auth::user()->customer->id)
                      ->firstOrFail();

        return view('front.checkout.order_success', compact('order'));
    }




     // --- ADDED: SSLCOMMERZ CALLBACK METHODS ---

    public function sslSuccess(Request $request)
    {

        

       
        $tran_id = $request->input('tran_id');
        $order = Order::where('invoice_no', $tran_id)->first();
//dd($tran_id);
       

        if ($order) {
            $sslc = new SslCommerzNotification();
            $validation = $sslc->orderValidate($request->all(), $tran_id, $order->total_amount, $order->currency);

            if ($validation) {
                $order->update([
                    'status' => 'pending',
                    'payment_status' => 'paid',
                    'total_pay' => $order->total_amount,
                    'due' => 0,
                    'cod' => 0
                ]);
  
                Session::forget('cart');
                Session::forget('coupon');

                return redirect()->route('order.success', ['orderId' => $order->id])
                                 ->with('success', 'Transaction is successfully completed!');
            }
        }
        return redirect()->route('cart.show')->with('error', 'Payment validation failed.');
    }




    public function sslFail(Request $request)
    {
        $tran_id = $request->input('tran_id');
        $order = Order::where('invoice_no', $tran_id)->first();
        if ($order) {
            $order->update(['status' => 'failed', 'payment_status' => 'failed']);
        }
        return redirect()->route('cart.show')->with('error', 'Transaction is failed.');
    }





    public function sslCancel(Request $request)
    {
        $tran_id = $request->input('tran_id');
        $order = Order::where('invoice_no', $tran_id)->first();
        if ($order) {
            $order->update(['status' => 'cancelled', 'payment_status' => 'cancelled']);
        }
        return redirect()->route('cart.show')->with('error', 'Transaction is cancelled.');
    }




    public function sslIpn(Request $request)
    {
        // IPN is an important validation step for asynchronous payment updates.
        // It's similar to the success callback but initiated by the SSLCommerz server.
        $tran_id = $request->input('tran_id');
        $order = Order::where('invoice_no', $tran_id)->where('payment_status', 'unpaid')->first();

        if ($order) {
             $sslc = new SslCommerzNotification();
            $validation = $sslc->orderValidate($request->all(), $tran_id, $order->total_amount, $order->currency);
            if ($validation) {
                $order->update([
                    'status' => 'pending',
                    'payment_status' => 'paid',
                    'total_pay' => $order->total_amount,
                    'due' => 0,
                    'cod' => 0
                ]);
                // You can add notifications (email, SMS) here
                return;
            }
        }
        // Log IPN failure if needed
    }
}

