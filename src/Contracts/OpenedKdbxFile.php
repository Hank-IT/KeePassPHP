<?php

declare(strict_types=1);

namespace KeePassPHP\Contracts;

interface OpenedKdbxFile
{
    public function getMajorVersion(): int;

    public function getHeaderHash(): ?string;

    public function getContent(): ?string;

    public function getRandomStream(): ?RandomStream;
}
