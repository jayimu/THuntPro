from urllib.parse import urlparse
import geocoder
import socket


def urltoip(urltarget):
    geoloc = ''
    target = ''
    finalip = ''
    result = ''

    try:
        target = urlparse(urltarget)
        result = target.netloc
        finalip = socket.gethostbyname(result)
        if finalip is not None:
            geoloc = geocoder.ip(finalip)
            if (geoloc is not None):
                return geoloc.city
            else:
                result = ''
                return result
        else:
            result = "Not Found"
            return result
    except Exception:
        result = "Not Found"
        return result


def compute_vt_url_id(full_url: str) -> str:
    """计算 VirusTotal URL 资源 ID（urlsafe base64 且去除 '=' 填充）。
    传入必须为包含协议的完整 URL，例如 'https://example.com/'.
    """
    try:
        import base64
        return base64.urlsafe_b64encode(full_url.encode()).decode().rstrip("=")
    except Exception:
        return ""
