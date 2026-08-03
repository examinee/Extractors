
ENUM_PATH = {
    1: "ApplicationPath",
    6: "%AppData%", 
}
FIELD_MAPS = {
    "7.2.0": {
        0:  ("c2",                   "c2list",    "high"),
        1:  ("botnet",               "str",       "low"),
        9:  ("install_path",         "enum_path", "high"),
        10: ("copy_file",            "utf16",     "high"),
        14: ("mutex",                "str",       "high"),
        16: ("unknown_16",          "enum_path", "low"),
        17: ("keylog_file",          "utf16",     "high"),
        21: ("screenshot_time",      "int",       "high"),
        24: ("take_screenshot_time", "int",       "high"),
        25: ("screenshot_path",      "enum_path", "high"),
        26: ("screenshot_folder",    "str",       "high"),
        36: ("audio_record_time",    "int",       "high"),
        37: ("audio_path",           "enum_path", "high"),
        38: ("audio_folder",         "str",       "high"),
        48: ("copy_folder",          "utf16",     "high"),
        49: ("keylog_folder",        "utf16",     "high"),
        52: ("unknown_52",         "str",       "low"),
    }
}
def normalize(raw: bytes, kind: str):
    if raw == b"":
        return None

    if kind == "c2list":
        out = []
        for item in raw.rstrip(b"\x1e").split(b"\x1e"):
            if not item:
                continue
            parts = item.decode("utf-8", "replace").split(":")
            if len(parts) == 3:
                out.append({"host": parts[0],
                            "port": int(parts[1]),
                            "tls":  parts[2] == "1"})
            else:
                out.append({"raw": item.decode("utf-8", "replace")})
        return out

    if kind == "utf16":
        return raw.decode("utf-16le", "replace").rstrip("\x00")

    if kind == "int":
        s = raw.decode("utf-8", "replace").strip("\x00")
        return int(s) if s.isdigit() else s

    if kind == "enum_path":
        s = raw.decode("utf-8", "replace").strip("\x00")
        if s.isdigit():
            return ENUM_PATH.get(int(s), f"unknown_enum_{s}")
        return s

    if kind == "bool":
        return raw not in (b"\x00", b"0")

    if kind == "str":
        return raw.decode("utf-8", "replace").rstrip("\x00")


def guess(raw):
    if raw == b'\x00':
        return False
    
    if raw == b'\x01':
        return True
    if len(raw) >= 4 and len(raw) % 2 == 0:
        if raw[1::2].count(0) >= len(raw) // 4:
            return raw.decode("utf-16le", "replace").rstrip("\x00")
    s = raw.decode("utf-8", "replace")
    if s.isprintable():
        return s
    return raw.hex()
