# PyInstaller Extractor ++

PyInstaller Extractor ++  is an enhancement from [PyInstaller Extractor](https://github.com/extremecoders-re/pyinstxtractor), to which some convenience features have been added. It not only extracts the file, but also calls [Uncomplye6](https://github.com/rocky/python-uncompyle6/) to decompile any files it might need.

Since it is no longer portable due to calling additional library , I decided to make it a standalone version rather than an upgrade.

## Prepare for use

```
pip install uncompyle6
```

## How to use 

The script can be run by passing the name of the exe as an argument.

```
$ python pyinstxtractor.py <filename>
X:\>python pyinstxtractor.py <filename>
```

It is recommended to run the script in the same version of Python which was used to generate the executable. This is to prevent unmarshalling errors(if any) while extracting the PYZ archive.

## Example

```
X:\> python pyinstxtractor.py test.exe
[*] File Format: PE
[+] Processing dist\test.exe
[+] Pyinstaller version: 2.1+
[+] Python version: 36
[+] Length of package: 5612452 bytes
[+] Found 59 files in CArchive
[+] Beginning extraction...please standby
[+] Possible entry point: pyiboot01_bootstrap.pyc
[+] Decompile it to pyiboot01_bootstrap.py
[+] Possible entry point: test.pyc
[+] Decompile it to test.py
[+] Found 133 files in PYZ archive
[+] Successfully extracted pyinstaller archive: dist\test.exe

You can now find python script what you want in the extracted directory
```

## Extracting Linux ELF binaries

Pyinstxtractor can extract Linux ELF binaries when it run on Linux. 

```
$ python3 pyinstxtractor.py client1
[*] Processing client1
[*] File Format: ELF
[+] Dump pydata to client1.pydata.dump
[*] Pyinstaller version: 2.1+
[*] Python version: 36
[*] Length of package: 5654048 bytes
[*] Found 32 files in CArchive
[*] Beginning extraction...please standby
[+] Possible entry point: pyiboot01_bootstrap.pyc
[+] Decompile it to pyiboot01_bootstrap.py
[+] Possible entry point: client.pyc
[+] Decompile it to client.py
[*] Found 134 files in PYZ archive
[+] The lib script Calculator maybe user defined
[+] Decompile it to PYZ-00.pyz_extracted/Calculator.py
[*] Successfully extracted pyinstaller archive: client1

You can now find python script what you want in the extracted directory
```

## License

GNU General Public License v3.0