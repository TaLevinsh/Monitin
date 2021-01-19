import os
import hashlib
from datetime import *
import requests

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


def Get_Report(Hash):
    API_Key = ''
    Url = 'https://www.virustotal.com/vtapi/v2/file/report'
    Params = {'apikey': API_Key, 'resource': Hash}
    Response = requests.get(Url, params=Params)
    Data = Response.json()
    return Data


def Parse_Report(TheHash):
    Data = Get_Report(TheHash)
    Phrase = 'Invalid resource'
    if Phrase in Data['verbose_msg']:
        return '0.9'
    else:
        X = Data['positives']
        Y = Data['total']
        return X/Y


def AllFiles():
    File_Lst = []
    Exe_Files = []
    DirectoryPath = raw_input('Insert The Directory Path -> ')
    for Root, Directories, Files in os.walk(DirectoryPath):
        Directories[:] = [D for D in Directories if D not in ['Thumbs']]
        for Filename in Files:
            FilePath = os.path.join(Root, Filename)
            FPath = open(FilePath, 'rb')
            File_Content = FPath.read()
            if File_Content[0:2] == "MZ":
                FilePath = os.path.join(Root, Filename)
                Exe_Files.append(FilePath)
            else:
                FilePath = os.path.join(Root, Filename)
                File_Lst.append(FilePath)

    DictF = {}
    for F in File_Lst:
        NameOnlyF = os.path.basename(F)
        Date_TimeF = datetime.fromtimestamp(os.path.getctime(F)).strftime('%Y-%m-%d %H:%M:%S')
        Rate = Parse_Report(FileToHash(F))
        DictF[NameOnlyF] = FileToHash(F), Date_TimeF, 'Not Executable', Rate
        print 'The', NameOnlyF, 'File MD5 Is', FileToHash(F), 'Was changed at', Date_TimeF, 'The Rate Is', Rate
    for E in Exe_Files:
        NameOnlyE = os.path.basename(E)
        Date_TimeE = datetime.fromtimestamp(os.path.getctime(E)).strftime('%Y-%m-%d %H:%M:%S')
        Rate = Parse_Report(FileToHash(E))
        DictF[NameOnlyE] = FileToHash(E), Date_TimeE, 'Executable', Rate
        print 'The', NameOnlyE, 'Executable File MD5 Is', FileToHash(E), 'And It Was changed at', Date_TimeE, 'The Rate Is', Rate


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
