from __future__ import annotations

import base64
import hashlib
import json
import os
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

import numpy as np
import qrcode
from PIL import Image
from PIL import ImageOps
from PIL.PngImagePlugin import PngInfo
from qrcode.constants import ERROR_CORRECT_Q
try:
    import zxingcpp
except ImportError:  # pragma: no cover - optional runtime dependency
    zxingcpp = None


@dataclass(slots=True)
class QrChunk:
    session_id: str
    index: int
    total: int
    payload_type: str
    checksum: str
    created_at: str
    expires_at: str
    payload: str


class QrPayloadService:
    FORMAT = "cryptosafe.qr.v1"
    COMPACT_FORMAT = "CSQR1"

    def __init__(self, validity_seconds: int = 300, chunk_size: int = 1400):
        self.validity_seconds = validity_seconds
        self.chunk_size = chunk_size

    def build_chunks(self, payload_type: str, payload: bytes | str, validity_seconds: int | None = None) -> list[dict]:
        raw = payload if isinstance(payload, bytes) else payload.encode("utf-8")
        encoded = base64.urlsafe_b64encode(raw).decode("ascii")
        created_at = datetime.now(timezone.utc)
        expires_at = created_at + timedelta(seconds=validity_seconds or self.validity_seconds)
        session_id = os.urandom(8).hex()
        nonce = os.urandom(8).hex()
        checksum = hashlib.sha256(
            f"{payload_type}:{session_id}:{nonce}:{created_at.isoformat(timespec='seconds')}".encode("utf-8") + raw
        ).hexdigest()
        segments = [encoded[i:i + self.chunk_size] for i in range(0, len(encoded), self.chunk_size)] or [""]
        total = len(segments)
        chunks = []
        for index, segment in enumerate(segments, start=1):
            chunk = {
                "format": self.FORMAT,
                "session_id": session_id,
                "index": index,
                "total": total,
                "payload_type": payload_type,
                "checksum": checksum,
                "nonce": nonce,
                "created_at": created_at.isoformat(timespec="seconds"),
                "expires_at": expires_at.isoformat(timespec="seconds"),
                "payload": segment,
            }
            chunks.append(chunk)
        return chunks

    def render_qr_images(self, chunks: list[dict], box_size: int = 8, border: int = 4) -> list[Image.Image]:
        images = []
        for chunk in chunks:
            payload_text = self._serialize_chunk(chunk)
            qr = qrcode.QRCode(
                version=None,
                error_correction=ERROR_CORRECT_Q,
                box_size=box_size,
                border=border,
            )
            qr.add_data(payload_text)
            qr.make(fit=True)
            image = qr.make_image(fill_color="black", back_color="white").convert("RGB")
            image.info["cryptosafe_qr_payload"] = payload_text
            images.append(image)
        return images

    def save_qr_images(self, images: list[Image.Image], paths: list[str]) -> None:
        if len(images) != len(paths):
            raise ValueError("images and paths length mismatch")
        for image, path in zip(images, paths):
            pnginfo = PngInfo()
            payload_text = image.info.get("cryptosafe_qr_payload")
            if payload_text:
                pnginfo.add_text("cryptosafe_qr_payload", payload_text)
            image.save(path, pnginfo=pnginfo)

    def decode_qr_images(self, image_paths: list[str]) -> tuple[str, bytes]:
        chunks = []
        for path in image_paths:
            found_for_path = False
            try:
                with Image.open(path) as pil_image:
                    image = pil_image.convert("RGB")
            except Exception as exc:
                raise ValueError(f"unable to read image: {path}") from exc
            if image is None:
                raise ValueError(f"unable to read image: {path}")
            for item in self._decode_candidates(image):
                chunks.append(json.loads(item))
                found_for_path = True
            if found_for_path:
                continue
            try:
                with Image.open(path) as pil_image:
                    payload_text = pil_image.info.get("cryptosafe_qr_payload")
                    if payload_text:
                        chunks.append(json.loads(self._normalize_chunk_text(payload_text)))
            except Exception:
                pass
        if not chunks:
            raise ValueError("no valid QR payloads found")
        return self.reassemble_chunks(chunks)

    def decode_frame(self, frame) -> list[str]:
        return self._decode_candidates(frame)

    def reassemble_chunks(self, chunks: list[dict]) -> tuple[str, bytes]:
        first = chunks[0]
        for chunk in chunks:
            self._validate_chunk(chunk)
            for field in ("session_id", "payload_type", "checksum", "total"):
                if chunk[field] != first[field]:
                    raise ValueError("QR chunk set mismatch")
        ordered = sorted(chunks, key=lambda item: int(item["index"]))
        if len(ordered) != int(first["total"]):
            raise ValueError("incomplete QR chunk set")
        encoded = "".join(item["payload"] for item in ordered)
        payload = base64.urlsafe_b64decode(encoded.encode("ascii"))
        checksum = hashlib.sha256(
            f"{first['payload_type']}:{first['session_id']}:{first['nonce']}:{first['created_at']}".encode("utf-8")
            + payload
        ).hexdigest()
        if checksum != first["checksum"]:
            raise ValueError("QR payload checksum mismatch")
        return first["payload_type"], payload

    def _validate_chunk(self, chunk: dict) -> None:
        if chunk.get("format") != self.FORMAT:
            raise ValueError("unsupported QR payload format")
        expires_at = datetime.fromisoformat(chunk["expires_at"])
        if datetime.now(timezone.utc) > expires_at:
            raise PermissionError("QR payload expired")

    @staticmethod
    def _decode_candidates(image) -> list[str]:
        pil_image = QrPayloadService._to_pil_image(image)
        candidates = []
        gray = ImageOps.grayscale(pil_image)
        candidates.append(gray)
        candidates.append(gray.resize((int(gray.width * 1.5), int(gray.height * 1.5)), resample=Image.Resampling.BILINEAR))
        candidates.append(gray.resize((int(gray.width * 2.0), int(gray.height * 2.0)), resample=Image.Resampling.NEAREST))
        candidates.append(gray.resize((max(1, int(gray.width * 0.75)), max(1, int(gray.height * 0.75))), resample=Image.Resampling.BOX))
        candidates.append(ImageOps.autocontrast(gray))
        candidates.append(gray.point(lambda px: 255 if px > 127 else 0))
        decoded = []
        seen = set()
        if zxingcpp is None:
            return decoded
        for candidate in candidates:
            for barcode in zxingcpp.read_barcodes(np.asarray(candidate)):
                item = barcode.text
                if item and item not in seen:
                    decoded.append(QrPayloadService._normalize_chunk_text(item))
                    seen.add(item)
        return decoded

    @staticmethod
    def _to_pil_image(image) -> Image.Image:
        if isinstance(image, Image.Image):
            return image.convert("RGB")
        if isinstance(image, np.ndarray):
            if image.ndim == 2:
                return Image.fromarray(image.astype(np.uint8), mode="L")
            if image.ndim == 3:
                return Image.fromarray(image.astype(np.uint8), mode="RGB")
        raise TypeError("unsupported frame type")

    @classmethod
    def _serialize_chunk(cls, chunk: dict) -> str:
        return "|".join(
            [
                cls.COMPACT_FORMAT,
                chunk["session_id"],
                str(chunk["index"]),
                str(chunk["total"]),
                chunk["payload_type"],
                chunk["checksum"],
                chunk["nonce"],
                chunk["created_at"],
                chunk["expires_at"],
                chunk["payload"],
            ]
        )

    @classmethod
    def _normalize_chunk_text(cls, text: str) -> str:
        text = text.strip()
        if text.startswith("{"):
            return text
        if not text.startswith(f"{cls.COMPACT_FORMAT}|"):
            raise ValueError("unsupported QR payload encoding")
        parts = text.split("|", 9)
        if len(parts) != 10:
            raise ValueError("malformed compact QR payload")
        chunk = {
            "format": cls.FORMAT,
            "session_id": parts[1],
            "index": int(parts[2]),
            "total": int(parts[3]),
            "payload_type": parts[4],
            "checksum": parts[5],
            "nonce": parts[6],
            "created_at": parts[7],
            "expires_at": parts[8],
            "payload": parts[9],
        }
        return json.dumps(chunk, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
