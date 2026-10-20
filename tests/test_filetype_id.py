import tempfile
import unittest
from pathlib import Path

from filetype_id import identify


class IdentifyTests(unittest.TestCase):
    def identify_bytes(self, name: str, content: bytes):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / name
            path.write_bytes(content)
            return identify(path)

    def test_detects_content_despite_wrong_extension(self):
        result = self.identify_bytes("photo.txt", b"\x89PNG\r\n\x1a\nrest")

        self.assertEqual(result.detected_type, "PNG image")
        self.assertEqual(result.mime_type, "image/png")
        self.assertFalse(result.extension_matches)

    def test_detects_matching_signature(self):
        result = self.identify_bytes("document.pdf", b"%PDF-1.7\n")

        self.assertEqual(result.detected_type, "PDF document")
        self.assertTrue(result.extension_matches)

    def test_text_extension_is_not_assumed_to_be_mismatch(self):
        result = self.identify_bytes("notes.md", b"plain UTF-8 notes\n")

        self.assertEqual(result.detected_type, "Text file (encoding or format not determined)")
        self.assertIsNone(result.extension_matches)

    def test_unknown_binary_is_reported(self):
        result = self.identify_bytes("payload.bin", b"\x00\xff\x00\xfe")

        self.assertEqual(result.detected_type, "Unknown binary data")
        self.assertIsNone(result.extension_matches)

    def test_detects_webp_inside_riff_container(self):
        result = self.identify_bytes("image.webp", b"RIFF\x00\x00\x00\x00WEBPdata")

        self.assertEqual(result.detected_type, "WebP image")
        self.assertTrue(result.extension_matches)


if __name__ == "__main__":
    unittest.main()
