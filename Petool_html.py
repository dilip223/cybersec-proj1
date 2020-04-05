import pefile
import os
import datetime
import peutils
import re
# importing modules
from flask import Flask, render_template

# declaring app name
app = Flask(__name__)

directory_in_str = str('C:/Users/pandi/PycharmProjects/PEtool/executables') #the directory file of all the executables

name_files=[]
date_files=[]
sec_files=[]
entry_files=[]
sec_files=[]
sect_files=[]
impo_files=[]
entry_length=[]
message_files=[]
for root, dir, files in os.walk(directory_in_str):
    for file1 in files:
        entri=[];
        temp_mess=[]
        print 'The file selected is: \t', file1
        pe = pefile.PE(os.path.join(root, file1), fast_load=True)
        name_files.append(file1)
#print the basic details
       # print 'The address of entry point', (pe.OPTIONAL_HEADER.AddressOfEntryPoint)
        date_read = datetime.datetime.fromtimestamp(pe.FILE_HEADER.TimeDateStamp).isoformat()
        print 'The Time Stamp', date_read
        print 'Number of Sections', (pe.FILE_HEADER.NumberOfSections)
        date_files.append(date_read)
        sec_files.append(pe.FILE_HEADER.NumberOfSections)


    #if the data is loaded with fast_load=true, we need to parse the directories
        pe.parse_data_directories()
        print ('The Imports are listed below as: ')
        el=0;
        entry_impo=[]
        for entry in pe.DIRECTORY_ENTRY_IMPORT: #this code determines the directory imports of the executable or dll
            print entry.dll
            entri.append(entry.dll)
            el+=1
            impo = []
            for imp in entry.imports:
               print [hex(imp.address), imp.name]
               impo.append([hex(imp.address), imp.name]) #uncomment if you want to see imports within import entries
            entry_impo.append(impo)
        entry_files.append(entri)
        entry_length.append(el)
        impo_files.append(entry_impo)
        try:
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                print hex(pe.OPTIONAL_HEADER.ImageBase + exp.address), exp.name, exp.ordinal
        except:
            pass

#This section is used to do a size check of the main sections. A flag is returned corresponding to section name if the
#difference is high between raw and virtual data
        diff = [] #create a list to store raw and virtual size difference
        size_flag = []
        upx_ind = 0
        sec=[]
        print 'The sections are:'
        for section in pe.sections:
            print (section.Name, hex(section.VirtualAddress),
                   section.Misc_VirtualSize, section.SizeOfRawData)
            sec.append([section.Name, hex(section.VirtualAddress), section.Misc_VirtualSize, section.SizeOfRawData])
            if section.Name.find('UPX')==0:
                upx_ind = 1
            diff_temp = abs(section.Misc_VirtualSize-section.SizeOfRawData)
            if diff_temp > 1000:
                size_flag.append(section.Name)
        temp_mess.append(['The size flags raised are',size_flag])
        if upx_ind == 1:
            temp_mess.append('The file has been packed with UPX')
        sect_files.append(sec)

        #STRINGS SECTION
        strings = []
        try:
            rsc_idx = [entry.id for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries]#.index(pefile.RESOURCE_TYPE['RT_STRING'])
            print 'The indexes for Resource Directory are' , rsc_idx
            for i,rt_indxs in enumerate(rsc_idx):
                string_directory = pe.DIRECTORY_ENTRY_RESOURCE.entries[i]
                for entry in string_directory.directory.entries:
                    # Get the RVA of the string data and
                    # size of the string data
                    data_rva = entry.directory.entries[0].data.struct.OffsetToData
                    size = entry.directory.entries[0].data.struct.Size
                    #print 'Directory entry at RVA', hex(data_rva), 'of size', hex(size)

                    # Retrieve the actual data and start processing the strings
                    #
                    data = pe.get_memory_mapped_image()[data_rva:data_rva + size]
                    offset = 0
                    while True:
                        # Exit once there's no more data to read
                        if offset >= size:
                            break
                        # Fetch the length of the unicode string
                        ustr_length = pe.get_word_from_data(data[offset:offset + 2], 0)
                        offset += 2
                        # If the string is empty, skip it
                        if ustr_length == 0:
                            continue
                        # Get the Unicode string
                        ustr = pe.get_string_u_at_rva(data_rva + offset, max_length=ustr_length)
                        offset += ustr_length * 2
                        strings.append(ustr)
                        #print 'String of length', ustr_length, 'at offset', offset

            path_str = []
            while ("" in strings):
                strings.remove("")

            print 'The strings extracted are'
            for i,stri in enumerate(strings):
                print i,stri
                count = 0
                urls = re.findall('(?:(?:https?|ftp):\/\/)?[\w/\-?=%.]+\.[\w/\-?=%.]+', stri)
                while count <= len(stri):
                    count += 1
                    new_string = stri.split(stri[:count], 1)
                    if os.path.exists(new_string[1]):
                        if stri.find(" \ ")==0:
                            path_str.append(stri)
                        break
            temp_mess.append(['The OS path strings extracted were = ', path_str])
            temp_mess.append(['The URL extracted from strings were = ', urls])
        except:
            temp_mess.append('The strings could not be extracted due to absence of resource directory')
            temp_mess.append('The strings could not be extracted due to absence of resource directory')
        signatures = peutils.SignatureDatabase('C:/Users/pandi/PycharmProjects/PEtool/UserDB.txt')
        matches = signatures.match(pe, ep_only=True)
        temp_mess.append(['The match found with the existing signature database (i.e the file packer signature) were = ', matches])
        message_files.append(temp_mess)
    print message_files

    @app.route('/')
    def homepage():
        return render_template("static_analysis.html", nam=name_files, dat=date_files, sec=sec_files, imp=entry_files
                               , sect=sect_files, msg=message_files)

    @app.route('/imp/')
    def imports():
        return render_template("imports.html", nam=name_files, ent=entry_files, imp=impo_files, el=entry_length)


    app.run(use_reloader=True, debug=True)
