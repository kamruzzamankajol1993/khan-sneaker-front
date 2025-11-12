<?php
namespace App\Library\SslCommerz;
use Illuminate\Support\Facades\Http;
abstract class AbstractSslCommerz implements SslCommerzInterface
{
    protected $apiUrl;
    protected $storeId;
    protected $storePassword;

    protected function setStoreId($storeID)
    {
        $this->storeId = $storeID;
    }

    protected function getStoreId()
    {
        return $this->storeId;
    }

    protected function setStorePassword($storePassword)
    {
        $this->storePassword = $storePassword;
    }

    protected function getStorePassword()
    {
        return $this->storePassword;
    }

    protected function setApiUrl($url)
    {
        $this->apiUrl = $url;
    }

    protected function getApiUrl()
    {
        return $this->apiUrl;
    }

    /**
     * @param $data
     * @param array $header
     * @param bool $setLocalhost
     * @return bool|string
     */
    /**
     * @param $data
     * @param array $header
     * @param bool $setLocalhost
     * @return bool|string
     */
    public function callToApi($data, $header = [], $setLocalhost = false)
    {
        // Start building the request
        $request = Http::asForm() // Send as application/x-www-form-urlencoded
                       ->withHeaders($header)
                       ->timeout(60);

        // Handle SSL verification for localhost
        if ($setLocalhost) {
            $request->withoutVerifying();
        }

        // Make the POST request
        $response = $request->post($this->getApiUrl(), $data);

        // Check if the request was successful
        if ($response->successful()) {
            return $response->body(); // Return the raw response body
        } else {
            // Optional: Log the detailed error
            // \Log::error('SSLCommerz API Error: ' . $response->status() . ' - ' . $response->body());
            return "FAILED TO CONNECT WITH SSLCOMMERZ API";
        }
    }

    /**
     * @param $response
     * @param string $type
     * @param string $pattern
     * @return false|mixed|string
     */
    public function formatResponse($response, $type = 'checkout', $pattern = 'json')
    {
        $sslcz = json_decode($response, true);

        if ($type != 'checkout') {
            return $sslcz;
        } else {
            if (!empty($sslcz['GatewayPageURL'])) {
                // this is important to show the popup, return or echo to send json response back
                if(!empty($this->getApiUrl()) && $this->getApiUrl() == 'https://securepay.sslcommerz.com') {
                   $response = json_encode(['status' => 'SUCCESS', 'data' => $sslcz['GatewayPageURL'], 'logo' => $sslcz['storeLogo']]);
                } else {
                    $response = json_encode(['status' => 'success', 'data' => $sslcz['GatewayPageURL'], 'logo' => $sslcz['storeLogo']]);
                }
            } else {
                if (strpos($sslcz['failedreason'],'Store Credential') === false) {
                    $message = $sslcz['failedreason'];
                } else {
                    $message = "Check the SSLCZ_TESTMODE and SSLCZ_STORE_PASSWORD value in your .env; DO NOT USE MERCHANT PANEL PASSWORD HERE.";
                }
                $response = json_encode(['status' => 'fail', 'data' => null, 'message' => $message]);
            }

            if ($pattern == 'json') {
                return $response;
            } else {
                echo $response;
            }
        }
    }

    /**
     * @param $url
     * @param bool $permanent
     */
    public function redirect($url, $permanent = false)
    {
        header('Location: ' . $url, true, $permanent ? 301 : 302);

        exit();
    }
}