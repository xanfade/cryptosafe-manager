import ctypes


def zeroize(buf: bytearray) -> None:
    """
    Обнуление чувствительных данных в памяти.
    """
    if not isinstance(buf, bytearray):
        raise TypeError("zeroize ожидает bytearray")

    length = len(buf)
    if length == 0:
        return

    # Получаем указатель на буфер bytearray и затираем его нулями
    ptr = (ctypes.c_char * length).from_buffer(buf)
    ctypes.memset(ptr, 0, length)
