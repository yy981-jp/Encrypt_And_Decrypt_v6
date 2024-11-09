#include <iostream>
#include <string>
#include <qrencode.h>
#include <png.h>
#include <cstring>
#include <iomanip>

std::string getTime() {
	auto t = std::time(nullptr);
	std::ostringstream oss;
	oss << std::put_time(std::localtime(&t),"%m%d%H%M");
	return oss.str();
}

bool SaveQRCodeToPNG(const std::string& text, const std::string& filename, int pixelSize = 10) {
    QRcode* qrcode = QRcode_encodeString(text.c_str(), 0, QR_ECLEVEL_H, QR_MODE_8, 1);
    if (!qrcode) {
        std::cerr << "Failed to encode QR Code" << std::endl;
        return false;
    }

    FILE* fp = fopen(filename.c_str(), "wb");
    if (!fp) {
        std::cerr << "Failed to open file for writing" << std::endl;
        QRcode_free(qrcode);
        return false;
    }

    png_structp png = png_create_write_struct(PNG_LIBPNG_VER_STRING, NULL, NULL, NULL);
    png_infop info = png_create_info_struct(png);
    setjmp(png_jmpbuf(png));

    png_init_io(png, fp);
    png_set_IHDR(png, info, qrcode->width * pixelSize, qrcode->width * pixelSize, 8, PNG_COLOR_TYPE_GRAY, PNG_INTERLACE_NONE, PNG_COMPRESSION_TYPE_DEFAULT, PNG_FILTER_TYPE_DEFAULT);
    png_write_info(png, info);

    // ピクセルサイズに合わせたデータの書き込み
    for (int y = 0; y < qrcode->width; ++y) {
        png_bytep row = (png_bytep)malloc(qrcode->width * pixelSize);
        memset(row, 0xFF, qrcode->width * pixelSize);  // 白で初期化
        for (int x = 0; x < qrcode->width; ++x) {
            if (qrcode->data[y * qrcode->width + x] & 1) {  // 黒い部分
                memset(row + x * pixelSize, 0, pixelSize);
            }
        }
        for (int i = 0; i < pixelSize; ++i) {
            png_write_row(png, row);
        }
        free(row);
    }

    png_write_end(png, NULL);
    png_destroy_write_struct(&png, &info);
    fclose(fp);
    QRcode_free(qrcode);
	return true;
}

int main(int argc, char *argv[]) {
	int pixelSize = 10;
	std::string path;
	switch(argc) {
		case 2: path = "QR" + getTime() + ".png"; break;
		case 3: path = std::string(argv[2]); break;
		case 4: path = std::string(argv[2]); pixelSize = std::stoi(argv[3]); break;
		default: std::cout << "yy981: 2024\nUsage: <Input> (<OutputPath>) (Size:default=10)"; return 0;
	}
    if (SaveQRCodeToPNG(std::string(argv[1]), path, pixelSize)) return 0; else return 1;;
}
