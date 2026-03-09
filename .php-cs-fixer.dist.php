<?php

declare(strict_types=1);

$finder = PhpCsFixer\Finder::create()
    ->in(__DIR__ . '/src')
    ->in(__DIR__ . '/tests')
    ->append([__FILE__])
    ->notPath('Playground.php')
    ->name('*.php');

return new PhpCsFixer\Config()
    ->setRiskyAllowed(true)
    ->setRules([
        '@PER-CS' => true,
        '@PHP8x4Migration' => true,
        'declare_strict_types' => true,
        'array_syntax' => ['syntax' => 'short'],
        'concat_space' => ['spacing' => 'one'],
        'line_ending' => true,
        'no_unused_imports' => true,
        'ordered_imports' => true,
        'single_line_empty_body' => true,
        'single_quote' => true,
    ])
    ->setFinder($finder);
