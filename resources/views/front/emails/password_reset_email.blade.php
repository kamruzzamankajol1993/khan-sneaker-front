<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Khan Sneaker - Password Reset OTP</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
    <style>
        /* Basic Reset and Body Styles */
        body {
            font-family: 'Inter', sans-serif;
            margin: 0;
            padding: 20px;
            background-color: #f0f2f5;
            color: #333;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            -webkit-font-smoothing: antialiased;
            -moz-osx-font-smoothing: grayscale;
        }

        /* Main container for the email content */
        .email-container {
            background-color: #ffffff;
            border-radius: 12px;
            padding: 40px;
            max-width: 580px;
            width: 100%;
            box-shadow: 0 4px 10px rgba(0, 0, 0, 0.05);
            box-sizing: border-box;
        }

        /* Header section with logo and brand name */
        .header {
            text-align: center; /* <<< CHANGE: Center align header content */
            margin-bottom: 24px;
        }

        /* Logo Image */
        .logo-image {
            max-width: 200px;
            height: auto;
        }
        
        /* <<< CHANGE: Center align main content text */
        .content {
            text-align: center;
        }

        /* Content section typography */
        .content p {
            font-size: 15px;
            line-height: 1.6;
            margin: 0 0 16px;
        }

        .content p:last-child {
            margin-bottom: 0;
        }

        /* OTP specific styling */
        .otp-text {
            font-size: 16px;
            font-weight: 500;
            margin: 24px 0 !important;
        }

        .otp-text strong {
            font-weight: 700;
            color: #000;
            font-size: 17px;
        }
        
        /* Footer section styling */
        .footer {
            margin-top: 32px;
            text-align: center; /* <<< CHANGE: Center align footer text */
        }

        .footer p {
            font-size: 15px;
            line-height: 1.6;
            margin: 0;
        }

        .footer strong {
            font-weight: 600;
        }

    </style>
</head>
<body>

    <div class="email-container">
        <header class="header">
            <img src="https://adminpanel.spotlightattires.com/public/uploads/1678859299.png" alt="Khan Sneaker Logo" class="logo-image">
        </header>

        <main class="content">
            <p style="font-weight: 900;color:#0f1531 !important;">Hello <strong style="color:#0f1531 !important;">{{ $name }}</strong>,</p>
            <p>We Have Received A Request To Reset Your  <strong style="color:#0f1531 !important;">Khan Sneaker!</strong> Account Password. <br>
            Please use the Link below to proceed.</p>
             <p style="text-align: center;">
        <a href="{{ $resetUrl }}" style="display: inline-block; padding: 12px 24px; background-color: #212529; color: #ffffff; text-decoration: none; border-radius: 5px;">Reset Password</a>
    </p>
    <p>This password reset link will expire in 60 minutes.</p>
    <p>If you did not request a password reset, no further action is required.</p>
        </main>
<footer class="footer">
            <p>Best regards,</p>
            <p><strong style="color:#0f1531 !important;">The Khan Sneaker Team</strong></p>
        </footer>
        
    </div>

</body>
</html>