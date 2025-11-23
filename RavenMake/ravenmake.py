import os
import pathlib
import shutil

RAVENPATH = pathlib.Path(__file__).parent.parent.absolute()

def get_lib_paths():
    paths = []
    with open(f"{RAVENPATH}/RavenMake/ravenlibs.txt") as f:
        for line in f:
            path = pathlib.Path(line.strip())
            paths.append(path)

    return paths

def main():
    paths = get_lib_paths()

    for path in paths:
        shutil.copy2(f"{RAVENPATH}/lib/libRaven32.a", path / "libRaven32.a")
        shutil.copy2(f"{RAVENPATH}/lib/libRaven64.a", path / "libRaven64.a")
        shutil.copy2(f"{RAVENPATH}/lib/Raven32.dll", path / "Raven32.dll")
        shutil.copy2(f"{RAVENPATH}/lib/Raven64.dll", path / "Raven64.dll")
        print(f"Replaced raven in '{path.absolute()}'")

    print("Done replacing Raven libraries!")


if __name__ == "__main__":
    main()
