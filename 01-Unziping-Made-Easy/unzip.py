import os
import shutil
import pathlib

def unzip():
    for entry in os.scandir():
        file_path = pathlib.Path(entry)
        if file_path.suffix == ".zip":
            shutil.unpack_archive(file_path)
            os.remove(file_path)

if __name__ == '__main__':
    print("Unzipping files...")
    unzip()
    print("Done!!!")
