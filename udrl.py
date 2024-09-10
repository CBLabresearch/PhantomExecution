import argparse
import binascii
import io
import itertools
import pefile


def execute(bytes):
    """
    A function to execute a user-supplied byte array. This function allocates memory, copies the supplied bytearray into
    it and creates a thread of execution.

    Parameters:
        bytes (bytearray): The user-supplied shellcode.
    """
    import ctypes

    ctypes.windll.kernel32.VirtualAlloc.restype = ctypes.c_void_p
    ctypes.windll.kernel32.RtlMoveMemory.argtypes = (ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t)
    ctypes.windll.kernel32.CreateThread.argtypes = (ctypes.c_int, ctypes.c_int, ctypes.c_void_p, ctypes.c_int, ctypes.c_int, ctypes.POINTER(ctypes.c_int))

    memory_allocation = ctypes.windll.kernel32.VirtualAlloc(ctypes.c_int(0), ctypes.c_int(len(bytes)), ctypes.c_int(0x3000), ctypes.c_int(0x40))
    if memory_allocation is not None:
        shellcode = (ctypes.c_char * len(bytes)).from_buffer_copy(bytes)
        print(f"[+] Start Address: {hex(memory_allocation)}")
        ctypes.windll.kernel32.RtlMoveMemory(ctypes.c_void_p(memory_allocation), shellcode, ctypes.c_size_t(len(bytes)))
        handle = ctypes.windll.kernel32.CreateThread(ctypes.c_int(0), ctypes.c_int(0), ctypes.c_void_p(memory_allocation), ctypes.c_int(0), ctypes.c_int(0), ctypes.pointer(ctypes.c_int(0)))
        if handle is not None:
            print("[+] Shellcode Executed")
            ctypes.windll.kernel32.WaitForSingleObject(handle, -1)


def xxd(name, data):
    """
    A function to convert a bytearray into an unsigned char array initializer.

    Parameters:
        name (str): The name of the unsigned char array.
        data (bytearray): The binary data to be converted into the array initializer.

    Returns:
        str: A string representation of the array initializer.
    """
    template = "unsigned char %s[] = {\n    %s\n};"
    hexs = map(lambda x: '0x%02x' % x, data)
    groups = itertools.zip_longest(*[iter(hexs)] * 16)
    groups = map(lambda x: ', '.join(filter(None, x)), groups)
    lines = ',\n    '.join(groups)
    return template % (name, lines)


def stomp_loader(ldr, rdll):
    """
    A function to overwrite a reflective DLL's ReflectiveLoader() function with a custom loader.

    Parameters:
        ldr (bytearray): The user-defined reflective loader
        rdll (bytearray): The input DLL

    Returns:
        bytearray: The updated DLL.
    """
    input_dll = pefile.PE(data=rdll)
    export_directory = [pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"]]
    input_dll.parse_data_directories(directories=export_directory)
    text_virtual_address = 0
    text_raw_data = 0

    for section in input_dll.sections:
        if b'.text' in section.Name:
            text_virtual_address = section.VirtualAddress
            text_raw_data = section.PointerToRawData

    for export in input_dll.DIRECTORY_ENTRY_EXPORT.symbols:
        # _ReflectiveLoader@4 is the name of the exported function in x86
        if (export.name == b"ReflectiveLoader" or export.name == b"_ReflectiveLoader@4"):
            RVA = export.address
            file_offset = RVA - text_virtual_address + text_raw_data
            print(f"[*] Found ReflectiveLoader - RVA: {hex(export.address)}\tFile Offset: {hex(file_offset)}")
            result = input_dll.set_bytes_at_offset(file_offset, ldr)
            if result:
                print("[+] Success: Applied UDRL to DLL")
                updated_rdll = bytearray(input_dll.__data__)
                return updated_rdll
            else:
                raise Exception("[-] Error: failed to apply UDRL")
    raise Exception("[-] Error: unable to find exported function")


def extract_custom_loader(peFile):
    """
    A function to extract the .text from a given executable.

    Parameters:
        peFile (bytearray): The user-supplied executable.

    Returns:
        bytearray: The user-defined reflective loader.
    """
    pe = pefile.PE(data=peFile)
    found_text_section = False
    for section in pe.sections:
        if b'.text' in section.Name:
            found_text_section = True
            data = section.get_data(ignore_padding=True)
            while data[-1] == 0:
                data = data[:-1]
            print("[+] Success: Extracted loader")
            return data
    if not found_text_section:
        peFile.close()
        raise Exception("[-] Error: loader not found")
    return


def cmd_run(args):
    """
    A command function that runs a given DLL via a user-defined reflective loader.

    Parameters:
        args (argparse.Namespace): The user supplied arguments (cmd, loader_exe, input_dll)
    """
    loader = extract_custom_loader(args.loader_exe.read())
    input_dll = args.input_dll.read()
    args.loader_exe.close()
    args.input_dll.close()
    print(f"[*] Size of loader: {len(loader)}")
    if args.cmd == "stomp-udrl":
        rdll = stomp_loader(loader, input_dll)
        execute(rdll)
    elif args.cmd == "prepend-udrl":
        execute(loader + input_dll)


def cmd_execute_payload(args):
    """
    A command function to execute abitrary shellcode.

    Parameters:
        args (argparse.Namespace): The user supplied arguments (payload_bin)
    """
    payload = args.payload_bin.read()
    args.payload_bin.close()
    execute(payload)


def cmd_xxd(args):
    """
    A command function that uses xxd() to convert a bytearray into an unsigned char array initializer.

    Parameters:
        args (argparse.Namespace): The user supplied arguments (binary_file, output_file)
    """
    file_output = xxd("debug_dll", args.binary_file.read())
    args.output_file.write(file_output)
    print(f"[+] Success: Written {args.binary_file.name} to {args.output_file.name}")


def cmd_extract(args):
    """
    A command function that uses extract_custom_loader() to extract a user-defined reflective loader from a given udrl-vs executable.

    Parameters:
        args (argparse.Namespace): The user supplied arguments (loader_exe, output_file)
    """
    loader = extract_custom_loader(args.loader_exe.read())
    args.output_file.write(loader)
    print(f"[+] Success: Written UDRL to {args.output_file.name}. Total Size: {len(loader)} bytes")


def main():
    print("""
            _      _               
           | |    | |              
  _   _  __| |_ __| |  _ __  _   _ 
 | | | |/ _` | '__| | | '_ \| | | |
 | |_| | (_| | |  | |_| |_) | |_| |
  \__,_|\__,_|_|  |_(_) .__/ \__, |
                      | |     __/ |
                      |_|    |___/ 
    """)

    parser = argparse.ArgumentParser(description='A simple Python utility to speed up development of User-Defined Reflective Loaders (UDRLs)')

    sub_parsers = parser.add_subparsers(required=True, dest="cmd")

    parser_xxd = sub_parsers.add_parser('xxd', help='Outputs a given binary in C include file style.')
    parser_xxd.add_argument('binary_file', type=argparse.FileType('rb'))
    parser_xxd.add_argument('output_file', type=argparse.FileType('w'))
    parser_xxd.set_defaults(func=cmd_xxd)

    parser_extract = sub_parsers.add_parser('extract-udrl', help='Extracts the .text section (the UDRL) from the provided executable and saves it to the specified output file.')
    parser_extract.add_argument('loader_exe', type=argparse.FileType('rb'))
    parser_extract.add_argument('output_file', type=argparse.FileType('wb'))
    parser_extract.set_defaults(func=cmd_extract)

    parser_stomp = sub_parsers.add_parser('stomp-udrl', help='Extracts the .text section (the UDRL) from the provided executable, overwrites the existing ReflectiveLoader() in the provided DLL and executes it.')
    parser_stomp.add_argument('input_dll', type=argparse.FileType('rb'))
    parser_stomp.add_argument('loader_exe', type=argparse.FileType('rb'))
    parser_stomp.set_defaults(func=cmd_run)

    parser_prepend = sub_parsers.add_parser('prepend-udrl', help='Extracts the .text section (the UDRL) from the provided executable, prepends it to the provided DLL and executes it.')
    parser_prepend.add_argument('input_dll', type=argparse.FileType('rb'))
    parser_prepend.add_argument('loader_exe', type=argparse.FileType('rb'))
    parser_prepend.set_defaults(func=cmd_run)

    parser_execute_payload = sub_parsers.add_parser('execute-payload', help='Executes the supplied payload file.')
    parser_execute_payload.add_argument('payload_bin', type=argparse.FileType('rb'))
    parser_execute_payload.set_defaults(func=cmd_execute_payload)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
