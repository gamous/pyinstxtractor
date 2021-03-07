"""
PyInstaller Extractor ++ v1.0 (Make it more useful)
Contributor : Gamous
E-mail : gamous(at)foxmail(dot)com
Web    : https://gamous.cn
Date   : 07-March-2021

Just do a litte work to improve it because the 
original author is not updated it. 

CHANGELOG
================================================
Version 1.0 (March 07, 2021)
-------------------------------------------------
- Use xdis.magics to get correct pyc magic
- Add support for Linux ELF
- Decompile enrty script and user-define lib


PyInstaller Extractor v1.9 (Supports pyinstaller 3.3, 3.2, 3.1, 3.0, 2.1, 2.0)
Author : Extreme Coders
E-mail : extremecoders(at)hotmail(dot)com
Web    : https://0xec.blogspot.com
Date   : 29-November-2017
Url    : https://sourceforge.net/projects/pyinstallerextractor/

For any suggestions, leave a comment on
https://forum.tuts4you.com/topic/34455-pyinstaller-extractor/

This script extracts a pyinstaller generated executable file.
Pyinstaller installation is not needed. The script has it all.

For best results, it is recommended to run this script in the
same version of python as was used to create the executable.
This is just to prevent unmarshalling errors(if any) while
extracting the PYZ archive.

Usage : Just copy this script to the directory where your exe resides
        and run the script with the exe file name as a parameter

C:\path\to\exe\>python pyinstxtractor.py <filename>
$ /path/to/exe/python pyinstxtractor.py <filename>

Licensed under GNU General Public License (GPL) v3.
You are free to modify this source.

CHANGELOG
================================================

Version 1.1 (Jan 28, 2014)
-------------------------------------------------
- First Release
- Supports only pyinstaller 2.0

Version 1.2 (Sept 12, 2015)
-------------------------------------------------
- Added support for pyinstaller 2.1 and 3.0 dev
- Cleaned up code
- Script is now more verbose
- Executable extracted within a dedicated sub-directory

(Support for pyinstaller 3.0 dev is experimental)

Version 1.3 (Dec 12, 2015)
-------------------------------------------------
- Added support for pyinstaller 3.0 final
- Script is compatible with both python 2.x & 3.x (Thanks to Moritz Kroll @ Avira Operations GmbH & Co. KG)

Version 1.4 (Jan 19, 2016)
-------------------------------------------------
- Fixed a bug when writing pyc files >= version 3.3 (Thanks to Daniello Alto: https://github.com/Djamana)

Version 1.5 (March 1, 2016)
-------------------------------------------------
- Added support for pyinstaller 3.1 (Thanks to Berwyn Hoyt for reporting)

Version 1.6 (Sept 5, 2016)
-------------------------------------------------
- Added support for pyinstaller 3.2
- Extractor will use a random name while extracting unnamed files.
- For encrypted pyz archives it will dump the contents as is. Previously, the tool would fail.

Version 1.7 (March 13, 2017)
-------------------------------------------------
- Made the script compatible with python 2.6 (Thanks to Ross for reporting)

Version 1.8 (April 28, 2017)
-------------------------------------------------
- Support for sub-directories in .pyz files (Thanks to Moritz Kroll @ Avira Operations GmbH & Co. KG)

Version 1.9 (November 29, 2017)
-------------------------------------------------
- Added support for pyinstaller 3.3
- Display the scripts which are run at entry (Thanks to Michael Gillespie @ malwarehunterteam for the feature request)
"""

from __future__ import print_function
import os
import struct
import marshal
import zlib
import sys
import  importlib
import types
from uuid import uuid4 as uniquename
from xdis.magics import magics
import uncompyle6

class CTOCEntry:
    def __init__(self, position, cmprsdDataSize, uncmprsdDataSize, cmprsFlag, typeCmprsData, name):
        self.position = position
        self.cmprsdDataSize = cmprsdDataSize
        self.uncmprsdDataSize = uncmprsdDataSize
        self.cmprsFlag = cmprsFlag
        self.typeCmprsData = typeCmprsData
        self.name = name


class PyInstArchive:
    PYINST20_COOKIE_SIZE = 24           # For pyinstaller 2.0
    PYINST21_COOKIE_SIZE = 24 + 64      # For pyinstaller 2.1+
    MAGIC = b'MEI\014\013\012\013\016'  # Magic number which identifies pyinstaller

    def __init__(self, path):
        self.filePath = path


    def open(self):
        try:
            self.fPtr = open(self.filePath, 'rb')
            self.fileSize = os.stat(self.filePath).st_size
        except:
            print('[*] Error: Could not open {0}'.format(self.filePath))
            return False
        return True


    def close(self):
        try:
            self.fPtr.close()
        except:
            pass


    def checkFile(self):
        print('[*] Processing {0}'.format(self.filePath))
        # Check File Format (ELF/PE)
        self.fPtr.seek(0)
        fileMagicNuber=self.fPtr.read(4)
        #print(fileMagicNuber)
        if fileMagicNuber==b'\x7fELF':
            print('[*] File Format: ELF')
            if os.name=='posix':
                os.system('objcopy --dump-section pydata={0}.pydata.dump {0}'.format(self.filePath))
                self.filePath='{0}.pydata.dump'.format(self.filePath)
                if not os.path.exists(self.filePath):
                    print('[!] Error : Fail to dump pydata from ELF')
                    return False
                else:
                    print('[+] Dump pydata to {0}'.format(self.filePath))
                    self.close()
                    self.open()
            else:
                print('[!] Run this script in Linux to handler ELF')
                return False
        elif fileMagicNuber==b'MZ\x90\x00':
            print('[*] File Format: PE')
        else:
            print('[*] File Format: UnKnown')
        # Check if it is a 2.0 archive
        self.fPtr.seek(self.fileSize - self.PYINST20_COOKIE_SIZE, os.SEEK_SET)
        magicFromFile = self.fPtr.read(len(self.MAGIC))

        if magicFromFile == self.MAGIC:
            self.pyinstVer = 20     # pyinstaller 2.0
            print('[*] Pyinstaller version: 2.0')
            return True

        # Check for pyinstaller 2.1+ before bailing out
        self.fPtr.seek(self.fileSize - self.PYINST21_COOKIE_SIZE, os.SEEK_SET)
        magicFromFile = self.fPtr.read(len(self.MAGIC))

        if magicFromFile == self.MAGIC:
            print('[*] Pyinstaller version: 2.1+')
            self.pyinstVer = 21     # pyinstaller 2.1+
            return True

        print('[*] Error : Unsupported pyinstaller version or not a pyinstaller archive')
        return False


    def getCArchiveInfo(self):
        try:
            if self.pyinstVer == 20:
                self.fPtr.seek(self.fileSize - self.PYINST20_COOKIE_SIZE, os.SEEK_SET)

                # Read CArchive cookie
                (magic, lengthofPackage, toc, tocLen, self.pyver) = \
                struct.unpack('!8siiii', self.fPtr.read(self.PYINST20_COOKIE_SIZE))

            elif self.pyinstVer == 21:
                self.fPtr.seek(self.fileSize - self.PYINST21_COOKIE_SIZE, os.SEEK_SET)

                # Read CArchive cookie
                (magic, lengthofPackage, toc, tocLen, self.pyver, pylibname) = \
                struct.unpack('!8siiii64s', self.fPtr.read(self.PYINST21_COOKIE_SIZE))

        except:
            print('[*] Error : The file is not a pyinstaller archive')
            return False

        print('[*] Python version: {0}'.format(self.pyver))

        # Overlay is the data appended at the end of the PE
        self.overlaySize = lengthofPackage
        self.overlayPos = self.fileSize - self.overlaySize
        self.tableOfContentsPos = self.overlayPos + toc
        self.tableOfContentsSize = tocLen

        print('[*] Length of package: {0} bytes'.format(self.overlaySize))
        return True


    def parseTOC(self):
        # Go to the table of contents
        self.fPtr.seek(self.tableOfContentsPos, os.SEEK_SET)

        self.tocList = []
        parsedLen = 0

        # Parse table of contents
        while parsedLen < self.tableOfContentsSize:
            (entrySize, ) = struct.unpack('!i', self.fPtr.read(4))
            nameLen = struct.calcsize('!iiiiBc')

            (entryPos, cmprsdDataSize, uncmprsdDataSize, cmprsFlag, typeCmprsData, name) = \
            struct.unpack( \
                '!iiiBc{0}s'.format(entrySize - nameLen), \
                self.fPtr.read(entrySize - 4))

            name = name.decode('utf-8').rstrip('\0')
            if len(name) == 0:
                name = str(uniquename())
                print('[!] Warning: Found an unamed file in CArchive. Using random name {0}'.format(name))

            self.tocList.append( \
                                CTOCEntry(                      \
                                    self.overlayPos + entryPos, \
                                    cmprsdDataSize,             \
                                    uncmprsdDataSize,           \
                                    cmprsFlag,                  \
                                    typeCmprsData,              \
                                    name                        \
                                ))

            parsedLen += entrySize
        print('[*] Found {0} files in CArchive'.format(len(self.tocList)))



    def extractFiles(self):
        print('[*] Beginning extraction...please standby')
        extractionDir = os.path.join(os.getcwd(), os.path.basename(self.filePath) + '_extracted')

        if not os.path.exists(extractionDir):
            os.mkdir(extractionDir)

        os.chdir(extractionDir)
        # Suggest pyc magic
        magic=magics[self.pyver/10]
        if self.pyver>=37:
            pycheader=magic+b'\x00'*12
        else:
            pycheader=magic+b'\x00'*8

        for entry in self.tocList:
            basePath = os.path.dirname(entry.name)
            if basePath != '':
                # Check if path exists, create if not
                if not os.path.exists(basePath):
                    os.makedirs(basePath)

            self.fPtr.seek(entry.position, os.SEEK_SET)
            data = self.fPtr.read(entry.cmprsdDataSize)

            if entry.cmprsFlag == 1:
                data = zlib.decompress(data)
                # Malware may tamper with the uncompressed size
                # Comment out the assertion in such a case
                assert len(data) == entry.uncmprsdDataSize # Sanity Check
            
            if os.path.splitext(entry.name)[1]=='':
                entry.name+='.pyc'
            
            f=open(entry.name, 'wb')
            if entry.typeCmprsData == b's':
                print('[+] Possible entry point: {0}'.format(entry.name))
                f.write(pycheader+data)
                f.close()
                f=open(entry.name[:-1],"w",encoding='utf8')
                try:
                    uncompyle6.main.decompile_file(entry.name,f)
                    print('[+] Decompile it to {0}'.format(entry.name[:-1]))
                    f.close()
                except:
                    print('[!] {0} not entry point.'.format(entry.name))
                    f.close()
                    os.remove(entry.name[:-1])
            elif entry.typeCmprsData == b'z' or entry.typeCmprsData == b'Z':
                f.write(data)
                f.close()
                self._extractPyz(entry.name)

    def _extractPyz(self, name):
        dirName =  name + '_extracted'
        # Create a directory for the contents of the pyz
        if not os.path.exists(dirName):
            os.mkdir(dirName)

        with open(name, 'rb') as f:
            pyzMagic = f.read(4)
            assert pyzMagic == b'PYZ\0' # Sanity Check

            pycHeader = f.read(4) # Python magic value

            if importlib.util.MAGIC_NUMBER != pycHeader:
                print('[!] Warning: The script is running in a different python version than the one used to build the executable')
                print('    Run this script in Python{0} to prevent extraction errors(if any) during unmarshalling'.format(self.pyver))

            (tocPosition, ) = struct.unpack('!i', f.read(4))
            f.seek(tocPosition, os.SEEK_SET)

            try:
                toc = marshal.load(f)
            except:
                print('[!] Unmarshalling FAILED. Cannot extract {0}. Extracting remaining files.'.format(name))
                return

            print('[*] Found {0} files in PYZ archive'.format(len(toc)))

            # From pyinstaller 3.1+ toc is a list of tuples
            if type(toc) == list:
                toc = dict(toc)

            for key in toc.keys():
                (ispkg, pos, length) = toc[key]
                f.seek(pos, os.SEEK_SET)

                fileName = key
                try:
                    # for Python > 3.3 some keys are bytes object some are str object
                    fileName = key.decode('utf-8')
                except:
                    pass

                # Make sure destination directory exists, ensuring we keep inside dirName
                destName = os.path.join(dirName, fileName.replace("..", "__"))
                destDirName = os.path.dirname(destName)
                destBaseName = os.path.basename(destName)
                if not os.path.exists(destDirName):
                    os.makedirs(destDirName)

                try:
                    data = f.read(length)
                    data = zlib.decompress(data)
                except:
                    print('[!] Error: Failed to decompress {0}, probably encrypted. Extracting as is.'.format(fileName))
                    open(destName + '.pyc.encrypted', 'wb').write(data)
                    continue

                with open(destName + '.pyc', 'wb') as pycFile:
                    pycFile.write(pycHeader)      # Write pyc magic
                    pycFile.write(b'\0' * 4)      # Write timestamp
                    if self.pyver>=37:
                        pycFile.write(b'\0' * 8)
                    elif self.pyver>=33:
                        pycFile.write(b'\0' * 4) # Size parameter added in Python 3.3
                    pycFile.write(data)
                
                if not importlib.util.find_spec(destBaseName):
                    print('[+] The lib script {0} maybe user defined'.format(destBaseName))
                    fd=open(destName + '.py',"w",encoding='utf8')
                    try:
                        uncompyle6.main.decompile_file(destName + '.pyc',fd)
                        print('[+] Decompile it to {0}'.format(destName + '.py'))
                        fd.close()
                    except:
                        print('[!] Error when decompile {0}'.format(destName))
                        fd.close()
                        os.remove(destName + '.py')

def main():
    if len(sys.argv) < 2:
        print('[*] Usage: pyinstxtractor.py <filename>')

    else:
        arch = PyInstArchive(sys.argv[1])
        if arch.open():
            if arch.checkFile():
                if arch.getCArchiveInfo():
                    arch.parseTOC()
                    arch.extractFiles()
                    arch.close()
                    print('[*] Successfully extracted pyinstaller archive: {0}'.format(sys.argv[1]))
                    print('')
                    print('You can now find python script what you want in the extracted directory')
                    return

            arch.close()


if __name__ == '__main__':
    main()