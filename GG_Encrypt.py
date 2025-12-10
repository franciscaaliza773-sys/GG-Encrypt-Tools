import io
import math
import struct
import zlib
import hashlib
import secrets
import numpy as np
import torch
from PIL import Image, ImageDraw, ImageFont
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256

MAGIC = b"GGIMGEX1"
VERSION = 1
PAYLOAD_MAGIC = b"GGFILE1"

# 顶部水印区域高度（像素）
HEADER_ROWS = 80
_KEY_PARTS = [
    0xb5ab048b1126700b1b2d923635a13c46,
    0xea6b79cedbd979e386172a9a2907d505,
    0x3af8907125b6f8ce40d47e214fe1c94d,
    0x01f8e6e786553001f510153d69c20844,
    0xc1ea994277a6947da27d78be0196317f,
    0x848061edcbf1d155b047f3520c6fcf48,
    0xda2976228119029638163c12ede335ef,
    0xd211333165690193b4e9d6c9bfa23056,
    0xcc395530757c3ef770e47561b2fb4fe0,
    0x2e29cc2d69decc95bd3271f8c9cc0011,
    0x4ef49ff0584073220f828f608cad2511,
    0x205bfaf8895bec538d9a973fd19d9658,
    0x2354ab6feb9c482fab47ff5e92a3d1a3,
    0xc47c3bf0aae4c20548fd94804ba71d72,
    0xfe6826a0075c2f5ae94d6f9ead446080,
    0x603cf7879111613dce05f226f750dafb,
]


def _get_public_key(custom_hex=None):
    """
    如果提供了 custom_hex（十六进制模数字符串），优先用自定义公钥；
    否则使用内置默认公钥。rsa_e 固定为 65537。
    """
    if custom_hex:
        s = str(custom_hex).strip()
        if s:
            try:
                n = int(s, 16)
                return RSA.construct((n, 65537))
            except Exception:
                # 自定义解析失败则退回默认公钥
                pass

    n = 0
    for part in _KEY_PARTS:
        n = (n << 128) | part
    return RSA.construct((n, 65537))


def _build_payload(data, filename):
    name = filename.encode("utf-8")
    if len(name) > 255:
        raise ValueError("文件名过长")
    buf = bytearray()
    buf += PAYLOAD_MAGIC
    buf += bytes([len(name)])
    buf += name
    buf += struct.pack(">I", len(data))
    buf += data
    return bytes(buf)


def _pack_session(aes_key, nonce, tag, pwd_hash):
    has_pwd = 1 if pwd_hash else 0
    header = bytes([
        1,
        len(aes_key),
        len(nonce),
        len(tag),
        has_pwd,
        0, 0, 0
    ])
    body = bytearray()
    body += aes_key
    body += nonce
    body += tag
    if pwd_hash:
        body += pwd_hash
    return header + bytes(body)


def _encrypt_payload_to_image(
    payload,
    public_key,
    password="",
    title="",
    skip_watermark_area=True,
    target_width=None,
):
    # 压缩
    compressed = zlib.compress(payload, level=9)

    # AES-GCM
    aes_key = secrets.token_bytes(32)
    nonce = secrets.token_bytes(12)
    cipher_aes = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher_aes.encrypt_and_digest(compressed)

    # 密码哈希（可选）
    password = password or ""
    pwd_hash = hashlib.sha256(password.encode("utf-8")).digest() if password else None

    # 会话块 + RSA-OAEP
    session_plain = _pack_session(aes_key, nonce, tag, pwd_hash)
    cipher_rsa = PKCS1_OAEP.new(public_key, hashAlgo=SHA256)
    enc_session = cipher_rsa.encrypt(session_plain)

    flags = 0
    if password:
        flags |= 0x01
    if skip_watermark_area:
        flags |= 0x02

    container = bytearray()
    container += MAGIC
    container += bytes([VERSION])
    container += bytes([flags])
    container += struct.pack(">H", len(enc_session))
    container += enc_session
    container += struct.pack(">I", len(ciphertext))
    container += ciphertext
    container = bytes(container)

    # 映射为像素，宽度自动计算
    bpp = 3
    total_data = len(container)
    pixels_needed = int(math.ceil(total_data / float(bpp)))

    if target_width is None or target_width < 16:
        target_width = max(64, int(math.sqrt(pixels_needed)))
    # 最小宽度 240，保证水印区域足够宽
    target_width = max(240, min(target_width, 4096))

    header_rows = HEADER_ROWS if skip_watermark_area else 0
    rows_for_data = int(math.ceil(pixels_needed / float(target_width)))
    height = header_rows + rows_for_data

    total_pixels = target_width * height
    total_bytes = total_pixels * bpp
    data_offset = header_rows * target_width * bpp

    if data_offset + total_data > total_bytes:
        raise RuntimeError("空间不足")

    buf = bytearray(total_bytes)
    if total_bytes - data_offset - total_data > 0:
        buf[data_offset + total_data:] = secrets.token_bytes(
            total_bytes - data_offset - total_data
        )
    buf[data_offset:data_offset + total_data] = container

    img = Image.frombytes("RGB", (target_width, height), bytes(buf))

    # 顶部黑底白字水印（固定字号）
    if title and skip_watermark_area and header_rows > 0:
        d = ImageDraw.Draw(img)
        d.rectangle([(0, 0), (target_width, header_rows - 1)], fill=(0, 0, 0))

        font_size = 40  # 固定字号
        font = None
        for fname in ("arial.ttf", "DejaVuSans.ttf", "NotoSansCJK-Regular.ttc"):
            try:
                font = ImageFont.truetype(fname, font_size)
                break
            except Exception:
                font = None
        if font is None:
            try:
                font = ImageFont.load_default()
            except Exception:
                font = None

        # 计算文字尺寸，用于居中
        if hasattr(d, "textbbox"):
            bbox = d.textbbox((0, 0), title, font=font)
            tw = bbox[2] - bbox[0]
            th = bbox[3] - bbox[1]
        else:
            if font is not None and hasattr(font, "getsize"):
                tw, th = font.getsize(title)
            else:
                tw, th = len(title) * 10, 24  # 简单估算

        x = max(0, (target_width - tw) // 2)
        y = max(0, (HEADER_ROWS - th) // 2)
        d.text((x, y), title, fill=(255, 255, 255), font=font)

    return img


class GG_IMGEncrypt:
    @classmethod
    def INPUT_TYPES(cls):
        return {
            "required": {
                "images": ("IMAGE",),
                "password": ("STRING", {
                    "default": "123456",
                    "multiline": False
                }),
                "title": ("STRING", {
                    "default": "GG_Encrypt",
                    "multiline": False
                }),
                "skip_watermark_area": ("BOOLEAN", {
                    "default": True
                }),
                "fps": ("INT", {
                    "default": 16,
                    "min": 1,
                    "max": 120
                }),
                "note": ("STRING", {
                    "default":
"此节点仅用于用户隐私保护，使用即承诺合法合规使用本工具，自愿承担全部风险与责任\n"
"建议设置密码，可以更大程度提升隐私保护安全性\n"
"需配合 小程序GGIMG加密 使用\n"
"fps: 用于后续将多张加密图片合成为视频时的播放帧率，可根据需要调整\n"
"password: 解码时需要的密码，30位以内（可选）\n"
"title: 标题，会显示在加密图片上方黑底白字水印区域（可选）\n"
"pub_key: RSA 公钥模数（十六进制字符串），可选，留空则使用默认公钥\n"
"注意：rsa_e 固定为 65537，无需输入\n"
"注意：本工具仅提供技术手段，请勿用于任何违法、侵权用途",
                    "multiline": True
                }),
                "pub_key": ("STRING", {
                    "default": "",
                    "multiline": False
                }),
            },
            "optional": {
                "audio": ("AUDIO",),  # 变为可选输入
            },
        }

    RETURN_TYPES = ("IMAGE",)  # 只输出 IMAGE
    FUNCTION = "encode"
    CATEGORY = "GG Tools"

    def encode(self, images, password, title,
               skip_watermark_area, fps, note, pub_key,
               audio=None):
        # images: [B,H,W,C] float32 0..1
        x = images[0].cpu().numpy()
        x = (np.clip(x, 0.0, 1.0) * 255).astype("uint8")
        pil_in = Image.fromarray(x, "RGB")

        buf = io.BytesIO()
        pil_in.save(buf, format="PNG")
        png_bytes = buf.getvalue()

        payload = _build_payload(png_bytes, "protected.png")
        pub = _get_public_key(pub_key)

        enc_pil = _encrypt_payload_to_image(
            payload=payload,
            public_key=pub,
            password=password,
            title=title,
            skip_watermark_area=skip_watermark_area,
            target_width=None,
        )

        enc_np = np.array(enc_pil).astype("float32") / 255.0
        enc_tensor = torch.from_numpy(enc_np)[None, ...]

        # audio 是可选输入，仅用于保持工作流结构，本节点不输出音频
        return (enc_tensor,)


NODE_CLASS_MAPPINGS = {
    "GG_IMGEncrypt": GG_IMGEncrypt,
}

NODE_DISPLAY_NAME_MAPPINGS = {
    "GG_IMGEncrypt": "GG IMGEncrypt",
}