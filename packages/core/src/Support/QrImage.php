<?php

namespace ClaudioDekker\LaravelAuth\Support;

use BaconQrCode\Renderer\Color\Alpha;
use BaconQrCode\Renderer\Color\Rgb;
use BaconQrCode\Renderer\Image\SvgImageBackEnd;
use BaconQrCode\Renderer\ImageRenderer;
use BaconQrCode\Renderer\RendererStyle\Fill;
use BaconQrCode\Renderer\RendererStyle\RendererStyle;
use BaconQrCode\Writer;

class QrImage
{
    /**
     * Create a new QR Image instance.
     *
     * @param  string  $contents
     */
    public function __construct(
        protected string $contents
    ) {
        //
    }

    /**
     * Fluently create a new QR Image instance.
     *
     * @param  string  $contents
     * @return static
     */
    public static function make(string $contents): self
    {
        return new static($contents);
    }

    /**
     * Convert the QR Image to an SVG string.
     *
     * @param  int  $size
     * @param  int  $margin
     * @param  int[]  $rgb
     * @return string
     */
    public function svg(int $size = 400, int $margin = 0, array $rgb = [0, 0, 0]): string
    {
        $renderer = new ImageRenderer(
            new RendererStyle($size, $margin, null, null, Fill::uniformColor(
                new Alpha(0, new Rgb(255, 255, 255)),
                new Rgb(...$rgb),
            )),
            new SvgImageBackEnd()
        );

        return (new Writer($renderer))->writeString($this->contents);
    }

    /**
     * Convert the QR Image to a SVG string, encoded as an image data URI.
     * Can be directly embedded in an HTML document <img> src attribute.
     *
     * @param  int  $size
     * @param  int  $margin
     * @param  int[]  $rgb
     * @return string
     */
    public function svgData(int $size = 400, int $margin = 0, array $rgb = [0, 0, 0]): string
    {
        return 'data:image/svg+xml;base64,'.base64_encode($this->svg($size, $margin, $rgb));
    }
}
