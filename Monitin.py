import os
import hashlib
from datetime import *


def FileToHash(Path):
    F = open(Path, 'rb')
    H = hashlib.md5()
    H.update(F.read())
    TheHash = H.hexdigest()
    return TheHash


def OneFile():
    FilePath = raw_input('Insert The File Path -> ')
    Hash = FileToHash(FilePath)
    print 'The File MD5 is:', Hash


def AllFiles():
    Extensions = ('.txt', '.jpg', '.py', '.pyc', '.h', '.json')
    File_Lst = []
    Exe_Files = []
    DirectoryPath = raw_input('Insert The Directory Path -> ')
    AllContent = os.listdir(DirectoryPath)
    for Root, Directories, Files in os.walk(DirectoryPath):
        Directories[:] = [D for D in Directories if D not in ['Thumbs']]
        for Filename in Files:
            if Filename.endswith(Extensions):
                FilePath = os.path.join(Root, Filename)
                File_Lst.append(FilePath)
            if Filename.endswith('.exe'):
                FilePath = os.path.join(Root, Filename)
                Exe_Files.append(FilePath)
    DictF = {}
    datetime.fromtimestamp(1529314845.5859969).strftime('%Y-%m-%d %H:%M:%S')
    for F in File_Lst:
        NameOnlyF = os.path.basename(F)
        print 'The', NameOnlyF, 'File MD5 Is', FileToHash(F)
        DictF[NameOnlyF] = FileToHash(F), os.path.getctime(F), 'Not Executable'
    for E in Exe_Files:
        NameOnlyE = os.path.basename(E)
        print 'The', NameOnlyE, 'Executable File MD5 Is', FileToHash(E)
        DictF[NameOnlyE] = FileToHash(E), os.path.getctime(E), 'Executable'
    print(DictF)


def main():
    print 'The HASHER'
    print '- - - - - -'
    Opt = input('[1] Calculate Hash For a File \n'
                '[2] Calculate Hashes For All Files Under a Directory\n'
                '>\t')
    if Opt == 1:
        OneFile()
    if Opt == 2:
        AllFiles()
    else:
        print 'Invalid Selection!'


if __name__ == '__main__':
    main()
