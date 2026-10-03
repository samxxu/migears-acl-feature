<?php

// A config whose only entry has a malformed path pattern — no leading slash.
// Loading it must fail and name the file, so a bad entry is traceable to the
// file it came from.
return [
    'roles' => [
        'editor' => [
            'api/posts' => ['GET'],
        ],
    ],
];
