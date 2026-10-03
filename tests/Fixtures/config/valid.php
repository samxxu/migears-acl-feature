<?php

// A valid config, used by the fromFile() tests: the example from the README,
// one role per shape, and one user carrying both a grant and a deny.
return [
    'default' => false,

    'roles' => [
        'admin' => [
            '*' => ['*'],
        ],
        'editor' => [
            '/api/posts' => ['GET', 'POST'],
            '/api/posts/*' => ['GET', 'PUT'],
        ],
        'viewer' => [
            '/api/posts' => ['GET'],
            '/api/posts/*' => ['GET'],
        ],
    ],

    'users' => [
        42 => [
            'grant' => [
                '/api/billing/*' => ['GET'],
            ],
            'deny' => [
                '/api/posts' => ['POST'],
                '/api/posts/*' => ['DELETE'],
            ],
        ],
    ],
];
