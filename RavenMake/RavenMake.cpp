#include <iostream>
#include <string>
#include <fstream>
#include <filesystem>

namespace fs = std::filesystem;

std::string libpath;

bool replace(std::string path_s, std::string file_s) {
    fs::path path(path_s);
    fs::path file = path / file_s; // Cursed
    if (!fs::exists(file))
        return false;

    // Replace the file with the one from the local folder "lib"
    fs::path new_file = libpath + "/" + file_s;
    if(!fs::exists(new_file)){
        std::cout << "\e[0;31mRavenMake error: The specified lib path does not contain the Raven libraries!\e[0;37m" << std::endl;
        exit(1);
    }

    if (fs::exists(file))
        fs::remove(file);

    fs::copy_file(new_file, file);
    return true;
}

int main(int argc, const char* argv[]) {
    std::cout << "Updating Ravens..." << std::endl;
    if(argc < 2)
        libpath = argv[0];
    else 
        libpath = argv[1];

    if(!fs::exists(fs::path(libpath))){
        std::cout << "\e[0;31mRavenMake error: The specified lib path does not exist!\e[0;37m" << std::endl;
        exit(1);
    }

    std::fstream stream;
    stream.open("ravenlibs.txt", std::ios::in);

    if(!stream.is_open()) {
        std::cout << "\e[0;31mRavenMake error: Could not find 'ravenlibs.txt'!\e[0;37m" << std::endl;
        exit(1);
    }

    std::string path;
    while(getline(stream, path)){
        if(!fs::exists(path)) {
            std::cout << "\e[0;31mRavenMake error: Path '" << path << "' does not exist!\e[0;37m" << std::endl;
            continue;
        }

        std::cout << "Replacing raven in '" << path << "'" << std::endl;

        bool replaced = false;
        replaced |= replace(path, "Raven32.dll");
        replaced |= replace(path, "Raven64.dll");
        replaced |= replace(path, "libRaven32.a");
        replaced |= replace(path, "libRaven64.a");

        if(!replaced)
            std::cout << "\e[0;33mRavenMake warning: No files found to be replaced in '" << path << "'\e[0;37m" << std::endl;

    }

    std::cout << "Done replacing Raven libraries!" << std::endl;

    return 0;
}