<?php

declare(strict_types=1);

namespace KeePassPHP\Readers;

/**
 * A Reader implementation reading from a PHP stream resource.
 */
final class ResourceReader extends Reader
{
    /** @var resource|null */
    private $resource;

    /**
     * Constructs a new ResourceReader instance around a PHP stream resource.
     *
     * @param resource $resource A PHP stream resource.
     */
    private function __construct($resource)
    {
        $this->resource = $resource;
    }

    /**
     * Creates a new ResourceReader instance reading the file $path.
     *
     * @param string $path A file path.
     *
     * @return self|null A new ResourceReader instance if $path could be opened and is
     *                   readable, null otherwise.
     */
    public static function openFile(string $path): ?self
    {
        if (!is_readable($path)) {
            return null;
        }

        $resource = fopen($path, 'rb');
        if ($resource === false) {
            return null;
        }

        return new self($resource);
    }

    public function read(int $n): ?string
    {
        if ($n < 1) {
            return '';
        }

        $resource = $this->resource;
        if (!is_resource($resource) || feof($resource)) {
            return null;
        }

        $chunk = fread($resource, $n);

        return $chunk === false ? null : $chunk;
    }

    public function readToTheEnd(): ?string
    {
        $resource = $this->resource;
        if (!is_resource($resource) || feof($resource)) {
            return null;
        }

        $contents = stream_get_contents($resource);

        return $contents === false ? null : $contents;
    }

    public function canRead(): bool
    {
        return is_resource($this->resource) && !feof($this->resource);
    }

    public function close(): void
    {
        if (!is_resource($this->resource)) {
            return;
        }

        fclose($this->resource);
        $this->resource = null;
    }
}
