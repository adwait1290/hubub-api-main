
ENCODING_BITMAP = "Bitmap (bmp)"
ENCODING_JP2 = "Joint Photographics Expert Group 2000 (jp2)"
ENCODING_JPEG = "Joint Photographics Expert Group (jpeg)"
ENCODING_PBM = "Portable Bitmap (pbm)"
ENCODING_PGM = "Portable Grayscale Map (pgm)"
ENCODING_PNG = "Portable Network Graphics (png)"
ENCODING_PPM = "Portable Pixmap (ppm)"
ENCODING_SR = "Sun Raster (sr)"
ENCODING_RAS = "Raster (ras)"
ENCODING_TIFF = "Tagged Image File Format (tiff)"

IMAGE_ENCODINGS = (
    ("bmp", ENCODING_BITMAP),
    ("jpeg", ENCODING_JPEG),
    ("jp2", ENCODING_JP2),
    ("pbm", ENCODING_PBM),
    ("pgm", ENCODING_PGM),
    ("png", ENCODING_PNG),
    ("ppm", ENCODING_PPM),
    ("sr", ENCODING_SR),
    ("ras", ENCODING_RAS),
    ("tiff", ENCODING_TIFF)
)


def get_available_encodings() -> str:
    return dict(IMAGE_ENCODINGS).values()


def get_encoding_acronym(encoding_title: str = None) -> str:
    return dict(
        map(lambda x: reversed(x), IMAGE_ENCODINGS)
    ).get(encoding_title or ENCODING_PNG)

