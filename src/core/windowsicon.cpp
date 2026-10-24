#include "windowsicon.h"

#include <QImage>
#include <QPixmap>

QIcon iconFromHICON(HICON icon)
{
    if (!icon) return QIcon();

    ICONINFO iconInfo = {};
    if (!GetIconInfo(icon, &iconInfo)) return QIcon();

    BITMAP bitmap = {};
    const HBITMAP sizeBitmap = iconInfo.hbmColor ? iconInfo.hbmColor : iconInfo.hbmMask;
    GetObjectW(sizeBitmap, sizeof(bitmap), &bitmap);

    const int width = bitmap.bmWidth > 0 ? bitmap.bmWidth : GetSystemMetrics(SM_CXSMICON);
    const int height = bitmap.bmHeight > 0 ? bitmap.bmHeight : GetSystemMetrics(SM_CYSMICON);

    BITMAPINFO bitmapInfo = {};
    bitmapInfo.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
    bitmapInfo.bmiHeader.biWidth = width;
    bitmapInfo.bmiHeader.biHeight = -height;
    bitmapInfo.bmiHeader.biPlanes = 1;
    bitmapInfo.bmiHeader.biBitCount = 32;
    bitmapInfo.bmiHeader.biCompression = BI_RGB;

    void *pixels = nullptr;
    HDC screenDc = GetDC(nullptr);
    HBITMAP dib = CreateDIBSection(screenDc, &bitmapInfo, DIB_RGB_COLORS, &pixels, nullptr, 0);
    HDC memoryDc = CreateCompatibleDC(screenDc);
    HGDIOBJ previousBitmap = SelectObject(memoryDc, dib);
    RECT bounds = {0, 0, width, height};
    FillRect(memoryDc, &bounds, static_cast<HBRUSH>(GetStockObject(BLACK_BRUSH)));
    DrawIconEx(memoryDc, 0, 0, icon, width, height, 0, nullptr, DI_NORMAL);
    SelectObject(memoryDc, previousBitmap);

    QImage image;
    if (dib && pixels) {
        image = QImage(static_cast<uchar *>(pixels), width, height, width * 4,
                       QImage::Format_ARGB32).copy();
    }

    DeleteDC(memoryDc);
    DeleteObject(dib);
    ReleaseDC(nullptr, screenDc);
    DeleteObject(iconInfo.hbmColor);
    DeleteObject(iconInfo.hbmMask);

    return image.isNull() ? QIcon() : QIcon(QPixmap::fromImage(image));
}