import ctypes

def is_elevated() -> bool:
    """
    Detects whether the current process has Administrator rights.
    Returns True if elevated, False otherwise.
    """
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except AttributeError:
        # Fallback if shell32 or IsUserAnAdmin is somehow unavailable
        return False
