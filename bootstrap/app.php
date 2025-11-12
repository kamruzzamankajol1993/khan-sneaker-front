<?php

use Illuminate\Foundation\Application;
use Illuminate\Foundation\Configuration\Exceptions;
use Illuminate\Foundation\Configuration\Middleware;

return Application::configure(basePath: dirname(__DIR__))
    ->withRouting(
        web: __DIR__.'/../routes/web.php',
        commands: __DIR__.'/../routes/console.php',
        health: '/up',
    )
    ->withMiddleware(function (Middleware $middleware): void {
         // Add CSRF token exceptions here
        $middleware->validateCsrfTokens(except: [
            'ssl/success',
            'ssl/fail',
            'ssl/cancel',
            'ssl/ipn',
            'bkash/success', // bKash Success URL
            'bkash/fail',    // bKash Fail URL
            'bkash/callback',  // bKash Callback URL
        ]);
    })
    ->withExceptions(function (Exceptions $exceptions): void {
        //
    })->create();
