from PIL import Image
import struct

MAGIC = b"ST1"  # header

def _bytes_to_bits(data: bytes):
    for b in data:
        for i in range(7, -1, -1):
            yield (b >> i) & 1

def _bits_to_bytes(bits):
    out = bytearray()
    cur = 0
    n = 0
    for bit in bits:
        cur = (cur << 1) | bit
        n += 1
        if n == 8:
            out.append(cur)
            cur = 0
            n = 0
    return bytes(out)

def _capacity_bytes(img: Image.Image) -> int:
    # On utilise 1 bit par canal RGB => 3 bits / pixel
    w, h = img.size
    total_bits = w * h * 3
    return total_bits // 8

def hide_bytes_in_image(in_img_path: str, out_img_path: str, payload: bytes) -> None:
    img = Image.open(in_img_path).convert("RGB")
    cap = _capacity_bytes(img)

    blob = MAGIC + struct.pack(">I", len(payload)) + payload
    if len(blob) > cap:
        raise ValueError(f"Payload trop gros: {len(blob)} bytes > capacité {cap} bytes. Utilise une image plus grande.")

    pixels = list(img.getdata())
    bits = list(_bytes_to_bits(blob))

    new_pixels = []
    bit_i = 0

    for (r, g, b) in pixels:
        if bit_i < len(bits):
            r = (r & 0xFE) | bits[bit_i]; bit_i += 1
        if bit_i < len(bits):
            g = (g & 0xFE) | bits[bit_i]; bit_i += 1
        if bit_i < len(bits):
            b = (b & 0xFE) | bits[bit_i]; bit_i += 1
        new_pixels.append((r, g, b))

    out = Image.new("RGB", img.size)
    out.putdata(new_pixels)
    out.save(out_img_path, format="PNG")  # PNG = sans perte (important)

def extract_bytes_from_image(img_path: str) -> bytes:
    img = Image.open(img_path).convert("RGB")
    pixels = list(img.getdata())

    bits = []
    for (r, g, b) in pixels:
        bits.append(r & 1)
        bits.append(g & 1)
        bits.append(b & 1)

    data = _bits_to_bytes(bits)

    if data[:3] != MAGIC:
        raise ValueError("Aucun payload ST1 trouvé (MAGIC absent).")

    length = struct.unpack(">I", data[3:7])[0]
    start = 7
    end = start + length
    if end > len(data):
        raise ValueError("Payload tronqué ou image invalide.")
    return data[start:end]
