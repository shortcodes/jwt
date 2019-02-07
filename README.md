# jwt
This is JWT Guard for Laravel Application

#.env

To use this package you have to put those variables to your *.env* file

  JWT_SECRET=
  JWT_TTL=60
  JWT_REFRESH_TTL=20160
  JWT_ALGO=HS256
  
# auth.php

You have to switch api driver to *jwt*

    'guards' => [
        'web' => [
            'driver' => 'session',
            'provider' => 'users',
        ],

        'api' => [
            'driver' => 'jwt',
            'provider' => 'users',
        ],
    ],
