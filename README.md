# cybersec-proj1
This project automates working with the PEfile (Portable Executive) files. Details of PEfile format can be found on 
(http://en.wikipedia.org/wiki/Portable_Executable). The project has two parts, the PEtool.py will go through the PEfiles in
a file directory and display the relevant information in the Pycharm dump. The second part PEtool_html will display the extracted information as a HTML page.

## Features

Some of the tasks that PEtool makes possible are:

  * Automatic directory scan for .exe and .dll files.
  * Analysis of sections' data and size, imports and exprts. 
  * File packer detection.
  * Reading strings from the resource section. String can only be viewed in Pycharm dump.
  * Warnings for suspicious and malformed values
  * Packer detection with [PEiD’s signatures]. Database text attached is downloaded from (http://web.archive.org/web/20160507191641/http://woodmann.com/BobSoft/Download.php?file=Files%2FOther%2FUserDB.zip)
  * HTML report of sections' information. 

## Dependencies

The project will need the PEfile obtained at (https://github.com/erocarrera/pefile). Additional libaraies and documents needed
are present in the requirements.txt attached.

## Usages

* Can be used in basic static analysis of executables and .dll files.
* File packer detection of malwares.
* Extraction of imports, export details and strings present in malwares.
* Future projects can involve automatic unpacking and file disassembly.
