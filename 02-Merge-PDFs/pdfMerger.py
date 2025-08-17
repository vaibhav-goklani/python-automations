import PyPDF2
import os
import pathlib

def merge():
    merger = PyPDF2.PdfMerger()
    for entry in os.scandir():
        file_path = pathlib.Path(entry)
        if file_path.suffix == ".pdf":
            pdf = PyPDF2.PdfReader(file_path)
            merger.append(pdf)
    
    merger.write("merged.pdf")

if __name__ == "__main__":
    print("Merging PDFs...")
    merge()
    print("Done!!!")
    print("Merged PDF saved as 'merged.pdf'.")
