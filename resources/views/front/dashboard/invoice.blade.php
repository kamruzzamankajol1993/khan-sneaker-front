<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="Content-Type" content="text/html; charset=utf-8"/>
    <title>Invoice #{{ $order->invoice_no }}</title>
    <style>
        body { font-family: 'dejavu sans', sans-serif; font-size: 14px; color: #333; }
        .container { width: 100%; margin: 0 auto; }
        .header, .footer { text-align: center; }
        .header h1 { margin: 0; }
        .invoice-details { margin-top: 20px; margin-bottom: 20px; }
        .invoice-details table { width: 100%; border-collapse: collapse; }
        .invoice-details td { padding: 5px; }
        .items-table { width: 100%; border-collapse: collapse; margin-top: 20px; }
        .items-table th, .items-table td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        .items-table th { background-color: #f2f2f2; }
        .text-right { text-align: right; }
        .total-section { margin-top: 20px; width: 40%; float: right; }
        .total-section table { width: 100%; }
        .total-section td { padding: 5px; }
        .bold { font-weight: bold; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
    <table style="width: 100%;">
        <tr>
            <td style="width: 50%;">
                <img src="{{$front_ins_url}}public/black.png" alt="Logo" style="width: 150px;">
            </td>
            <td style="width: 50%; text-align: right;">
                <h2 style="margin: 0;">INVOICE</h2>
                <p style="margin: 0; line-height: 1.5;">
                    <strong>Spotlight Attires</strong><br>
                    {{$front_ins_add}}<br>
                    {{$front_ins_phone}}<br>
                    {{$front_ins_email}}<br>
                    www.spotlightattires.com
                </p>
            </td>
        </tr>
    </table>
    <hr>
</div>

        <div class="invoice-details">
            <table>
                <tr>
                    <td style="width: 50%;">
                        <strong>Billed To:</strong><br>
                        {{ $order->customer->name }}<br>
                        {{ $order->shipping_address }}<br>
                        {{ $order->customer->email }}<br>
                        {{ $order->customer->phone }}
                        @if($order->customer->secondary_phone)
                            <br>{{ $order->customer->secondary_phone }} (Secondary)
                        @endif
                    </td>
                    <td style="width: 50%;" class="text-right">
                        <strong>Invoice #:</strong> {{ $order->invoice_no }}<br>
                        <strong>Order Date:</strong> {{ \Carbon\Carbon::parse($order->created_at)->format('d M, Y') }}<br>
                        <strong>Payment Status:</strong> <span class="bold">{{ ucfirst($order->payment_status) }}</span>
                    </td>
                </tr>
            </table>
        </div>

        <table class="items-table">
            <thead>
                <tr>
                    <th>#</th>
                    <th>Product Name</th>
                    <th class="text-right">Quantity</th>
                    <th class="text-right">Unit Price</th>
                    <th class="text-right">Total</th>
                </tr>
            </thead>
            <tbody>
                @foreach($order->orderDetails as $index => $detail)
                <tr>
                    <td>{{ $index + 1 }}</td>
                    <td>
                        {{ $detail->product->name ?? 'N/A' }}
                        <br><small>Size: {{ $detail->size }}, Color: {{ $detail->color }}</small>
                    </td>
                    <td class="text-right">{{ $detail->quantity }}</td>
                    <td class="text-right">{{ number_format($detail->unit_price, 2) }}</td>
                    <td class="text-right">{{ number_format($detail->subtotal, 2) }}</td>
                </tr>
                @endforeach
            </tbody>
        </table>

        <div class="total-section">
            <table>
                <tr>
                    <td>Subtotal:</td>
                    <td class="text-right">{{ number_format($order->subtotal, 2) }}</td>
                </tr>
                <tr>
                    <td>Shipping:</td>
                    <td class="text-right">{{ number_format($order->shipping_cost, 2) }}</td>
                </tr>
                 @if($order->discount > 0)
                <tr>
                    <td>Discount:</td>
                    <td class="text-right">- {{ number_format($order->discount, 2) }}</td>
                </tr>
                @endif
                <tr>
                    <td class="bold">Grand Total:</td>
                    <td class="text-right bold">{{ number_format($order->total_amount, 2) }}</td>
                </tr>
            </table>
        </div>

        <div style="clear: both;"></div>

        <div class="footer" style="margin-top: 50px;">
            <p>Thank you for shopping with Spotlight Attires!</p>
        </div>
    </div>
</body>
</html>