// psm_encryptor_test.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include "../psm_encryptor/psm_encryptor.hpp"


int main()
{

    FILE* kdev_fd = NULL;
    FILE* hkapp_fd = NULL;
    fopen_s(&kdev_fd, "test/kdev.p12", "rb");
    fopen_s(&hkapp_fd, "test/psm.khapp", "rb");

    fseek(kdev_fd, 0, SEEK_END);
    size_t kdev_size = ftell(kdev_fd);
    fseek(kdev_fd, 0, SEEK_SET);

    fseek(hkapp_fd, 0, SEEK_END);
    size_t khapp_size = ftell(hkapp_fd);
    fseek(hkapp_fd, 0, SEEK_SET);

    uint8_t* kdev = (uint8_t*)malloc(kdev_size);
    uint8_t* khapp = (uint8_t*)malloc(khapp_size);

    fread(kdev, 1, kdev_size, kdev_fd);
    fread(khapp, 1, khapp_size, hkapp_fd);

    ScePsmEdataStatus stat = scePsmEdataEncrypt("test/Application/apple.psmvideo", "test/Application/apple.psmvideo.encrypted", "/Application/apple.psmvideo",
        ScePsmEdataType::ReadonlyIcvAndCrypto, kdev, kdev_size, (PsmHkapp*)khapp, khapp_size);

    free(kdev);
    free(khapp);
}

// Run program: Ctrl + F5 or Debug > Start Without Debugging menu
// Debug program: F5 or Debug > Start Debugging menu

// Tips for Getting Started: 
//   1. Use the Solution Explorer window to add/manage files
//   2. Use the Team Explorer window to connect to source control
//   3. Use the Output window to see build output and other messages
//   4. Use the Error List window to view errors
//   5. Go to Project > Add New Item to create new code files, or Project > Add Existing Item to add existing code files to the project
//   6. In the future, to open this project again, go to File > Open > Project and select the .sln file
