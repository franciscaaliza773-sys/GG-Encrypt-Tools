from .GG_Encrypt import GG_IMGEncrypt

NODE_CLASS_MAPPINGS = {
    "GG_IMGEncrypt": GG_IMGEncrypt
}

NODE_DISPLAY_NAME_MAPPINGS = {
    "GG_IMGEncrypt": "GG Encrypt Tool"
}

__all__ = ["NODE_CLASS_MAPPINGS", "NODE_DISPLAY_NAME_MAPPINGS"]