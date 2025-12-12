import io
import math
import struct
import zlib
import hashlib
import secrets
import zipfile
import wave
import numpy as np
import torch
import imageio
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
    if custom_hex:
        s = str(custom_hex).strip()
        if s:
            try:
                n = int(s, 16)
                return RSA.construct((n, 65537))
            except Exception:
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
    compressed = zlib.compress(payload, level=9)
    aes_key = secrets.token_bytes(32)
    nonce = secrets.token_bytes(12)
    cipher_aes = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher_aes.encrypt_and_digest(compressed)

    password = password or ""
    pwd_hash = hashlib.sha256(password.encode("utf-8")).digest() if password else None

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

    bpp = 3
    total_data = len(container)
    pixels_needed = int(math.ceil(total_data / float(bpp)))

    if target_width is None or target_width < 16:
        target_width = max(64, int(math.sqrt(pixels_needed)))
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

    if title and skip_watermark_area and header_rows > 0:
        d = ImageDraw.Draw(img)
        d.rectangle([(0, 0), (target_width, header_rows - 1)], fill=(0, 0, 0))

        font_size = 40
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

        if hasattr(d, "textbbox"):
            bbox = d.textbbox((0, 0), title, font=font)
            tw = bbox[2] - bbox[0]
            th = bbox[3] - bbox[1]
        else:
            if font is not None and hasattr(font, "getsize"):
                tw, th = font.getsize(title)
            else:
                tw, th = len(title) * 10, 24

        x = max(0, (target_width - tw) // 2)
        y = max(0, (header_rows - th) // 2)
        d.text((x, y), title, fill=(255, 255, 255), font=font)

    return img


def _convert_audio_to_wav_bytes(audio_dict):
    waveform = audio_dict['waveform']
    sample_rate = audio_dict['sample_rate']
    if waveform.dim() == 3:
        waveform = waveform[0]
    audio_np = waveform.cpu().numpy()
    audio_np = (np.clip(audio_np, -1.0, 1.0) * 32767).astype(np.int16)
    if audio_np.shape[0] < audio_np.shape[1]: 
        audio_np = audio_np.T
    channels = audio_np.shape[1] if audio_np.ndim > 1 else 1
    io_buf = io.BytesIO()
    with wave.open(io_buf, 'wb') as wf:
        wf.setnchannels(channels)
        wf.setsampwidth(2)
        wf.setframerate(sample_rate)
        wf.writeframes(audio_np.tobytes())
    return io_buf.getvalue()


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
                "video_quality": ("INT", {
                    "default": 6, 
                    "min": 0, 
                    "max": 10,
                    "step": 1,
                    "display": "number",
                    "label": "Video Quality (10=Best)" 
                }),
                "note": ("STRING", {
                    "default":
"此节点仅用于用户隐私保护，使用即承诺合法合规使用本工具，自愿承担全部风险与责任\n"
"建议设置密码，可以更大程度提升隐私保护安全性\n"
"需配合 GG解密工具 使用\n"
"fps: 若输入是多帧图片(视频)，将压缩为MP4后加密\n"
"video_quality: 视频压缩质量 (0-10)，越高越清晰但体积越大\n"
"password: 解码时需要的密码，默认 123456\n"
"title: 标题，会显示在加密图片上方黑底白字水印区域（可选）\n"
"pub_key: RSA 公钥模数（十六进制），可选\n",
                    "multiline": True
                }),
                "pub_key": ("STRING", {
                    "default": "",
                    "multiline": False
                }),
            },
            "optional": {
                "audio": ("AUDIO",),
            }
        }

    RETURN_TYPES = ("IMAGE",)
    FUNCTION = "encode"
    CATEGORY = "GG Tools"

    def encode(self, images, password, title, skip_watermark_area, fps, video_quality, note, pub_key, audio=None):
        
        batch_size = images.shape[0]
        
        # 1. 准备核心数据 (图片 or MP4)
        if batch_size > 1:
            # === 视频模式 ===
            print(f"[GG_Encrypt] Detected Video Input ({batch_size} frames). Compressing to MP4...")
            frames = (images.cpu().numpy() * 255).clip(0, 255).astype(np.uint8)
            video_buf = io.BytesIO()
            crf = int(50 - (video_quality / 10.0) * 32)
            
            try:
                with imageio.get_writer(video_buf, format='mp4', fps=fps, codec='libx264', quality=None, pixelformat='yuv420p', macro_block_size=None, ffmpeg_params=['-crf', str(crf)]) as writer:
                    for frame in frames:
                        writer.append_data(frame)
                main_data_bytes = video_buf.getvalue()
                main_filename = "video.mp4"
            except Exception as e:
                print(f"[GG_Encrypt] Video compression failed: {e}. Falling back to first frame.")
                pil_in = Image.fromarray(frames[0], "RGB")
                img_buf = io.BytesIO()
                pil_in.save(img_buf, format="PNG")
                main_data_bytes = img_buf.getvalue()
                main_filename = "image.png"
                
        else:
            # === 单图模式 ===
            x = images[0].cpu().numpy()
            x = (np.clip(x, 0.0, 1.0) * 255).astype("uint8")
            pil_in = Image.fromarray(x, "RGB")
            img_buf = io.BytesIO()
            pil_in.save(img_buf, format="PNG")
            main_data_bytes = img_buf.getvalue()
            main_filename = "image.png"

        # 2. 混合音频
        if audio is not None:
            try:
                wav_bytes = _convert_audio_to_wav_bytes(audio)
                zip_buf = io.BytesIO()
                with zipfile.ZipFile(zip_buf, 'w', zipfile.ZIP_DEFLATED) as zf:
                    zf.writestr(main_filename, main_data_bytes)
                    zf.writestr("audio.wav", wav_bytes)
                final_data = zip_buf.getvalue()
                final_name = "bundle.zip"
            except Exception as e:
                print(f"[GG_Encrypt] Audio Error: {e}")
                final_data = main_data_bytes
                final_name = main_filename
        else:
            final_data = main_data_bytes
            final_name = main_filename

        # 3. 加密输出
        payload = _build_payload(final_data, final_name)
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

        return (enc_tensor,)


NODE_CLASS_MAPPINGS = {
    "GG_IMGEncrypt": GG_IMGEncrypt,
}

NODE_DISPLAY_NAME_MAPPINGS = {
    "GG_IMGEncrypt": "GG IMGEncrypt",
}