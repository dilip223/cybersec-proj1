import pefile
import os
import datetime
import peutils
directory_in_str = str('C:/Users/pandi/PycharmProjects/PEtool/executables') #the directory file of all the executables

for root, dir, files in os.walk(directory_in_str):
    for file1 in files:
        print 'The file selected is: \t',file1
        pe = pefile.PE(os.path.join(root, file1), fast_load=True)

#print the basic details
       # print 'The address of entry point', (pe.OPTIONAL_HEADER.AddressOfEntryPoint)
        date_read = datetime.datetime.fromtimestamp(pe.FILE_HEADER.TimeDateStamp).isoformat()
        print 'The Time Stamp', date_read
        print 'Number of Sections', (pe.FILE_HEADER.NumberOfSections)


    #if the data is loaded with fast_load=true, we need to parse the directories
        pe.parse_data_directories()
        print ('The Imports are listed below as: ')
        for entry in pe.DIRECTORY_ENTRY_IMPORT: #this code determines the directory imports of the executable or dll
            print entry.dll
            for imp in entry.imports:
                print '\t', hex(imp.address), imp.name



#This section is used to do a size check of the main sections. A flag is returned corresponding to section name if the
#difference is high between raw and virtual data
        diff=[] #create a list to store raw and virtual size difference
        size_flag=[]
        for section in pe.sections:
            print (section.Name, hex(section.VirtualAddress),
            section.Misc_VirtualSize, section.SizeOfRawData )
            diff_temp=abs(section.Misc_VirtualSize-section.SizeOfRawData)
            if diff_temp>1000:
                size_flag.append(section.Name)
        print 'The size flags raised are',size_flag

        strings = []
        rt_string_idx= [entry.id for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries].index(pefile.RESOURCE_TYPE['RT_STRING'])
        rt_string_directory = pe.DIRECTORY_ENTRY_RESOURCE.entries[rt_string_idx]
        for entry in rt_string_directory.directory.entries:

            # Get the RVA of the string data and
            # size of the string data
            #
            data_rva = entry.directory.entries[0].data.struct.OffsetToData
            size = entry.directory.entries[0].data.struct.Size
            print 'Directory entry at RVA', hex(data_rva), 'of size', hex(size)

            # Retrieve the actual data and start processing the strings
            #
            data = pe.get_memory_mapped_image()[data_rva:data_rva + size]
            offset = 0
            while True:
                # Exit once there's no more data to read
                if offset >= size:
                    break
                # Fetch the length of the unicode string
                #
                ustr_length = pe.get_word_from_data(data[offset:offset + 2], 0)
                offset += 2

                # If the string is empty, skip it
                if ustr_length == 0:
                    continue

                # Get the Unicode string
                #
                ustr = pe.get_string_u_at_rva(data_rva + offset, max_length=ustr_length)
                offset += ustr_length * 2
                strings.append(ustr)
                #print 'String of length', ustr_length, 'at offset', offset

        print rt_string_directory.directory.entries

        for i,stri in enumerate(strings):
            print i,stri
        signatures = peutils.SignatureDatabase('C:/Users/pandi/PycharmProjects/PEtool/UserDB.txt')
        matches = signatures.match(pe, ep_only=True)
        print matches

