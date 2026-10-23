import struct
import sys
from pathlib import Path


# ============================================================
# Block 1: File Loading
# ============================================================

def read_pe_file(file_path):
    """
    Reads the entire PE file into memory as raw bytes.
    """

    path = Path(file_path)

    if not path.is_file():
        print(f"Error: {file_path} is not a valid file.")
        return None

    return path.read_bytes()


# ============================================================
# Block 2: DOS Header
# ============================================================

def parse_dos_header(data):
    """
    Parses the DOS header.

    Important fields:
        MZ signature
        e_lfanew -> file offset of the PE header
    """

    # Need at least 64 bytes to reach e_lfanew at offset 0x3C
    if len(data) < 0x40:
        print("Error: File is too small for a valid DOS header.")
        return None

    magic = data[:2]

    if magic != b"MZ":
        print("Error: Invalid DOS signature. Expected MZ.")
        return None

    # At offset 0x3C:
    # read a 4-byte little-endian unsigned integer
    e_lfanew = struct.unpack_from(
        "<I",
        data,
        0x3C
    )[0]

    if e_lfanew + 4 > len(data):
        print("Error: e_lfanew points outside the file.")
        return None

    return {
        "magic": magic,
        "e_lfanew": e_lfanew
    }


# ============================================================
# Block 3: PE Signature
# ============================================================

def parse_pe_signature(data, e_lfanew):
    """
    Checks for the PE signature:

        PE\\0\\0
    """

    pe_signature = data[
        e_lfanew:e_lfanew + 4
    ]

    if pe_signature != b"PE\x00\x00":
        print("Error: Invalid PE signature.")
        return None

    return pe_signature


# ============================================================
# Block 4: COFF Header
# ============================================================

def parse_coff_header(data, e_lfanew):
    """
    COFF Header begins immediately after the
    4-byte PE signature.

    COFF header size = 20 bytes.
    """

    coff_offset = e_lfanew + 4
    coff_size = 20

    if coff_offset + coff_size > len(data):
        print("Error: Invalid COFF Header.")
        return None

    (
        machine,
        number_of_sections,
        time_date_stamp,
        pointer_to_symbol_table,
        number_of_symbols,
        size_of_optional_header,
        characteristics
    ) = struct.unpack_from(
        "<HHIIIHH",
        data,
        coff_offset
    )

    return {
        "offset": coff_offset,
        "machine": machine,
        "number_of_sections": number_of_sections,
        "time_date_stamp": time_date_stamp,
        "pointer_to_symbol_table": pointer_to_symbol_table,
        "number_of_symbols": number_of_symbols,
        "size_of_optional_header": size_of_optional_header,
        "characteristics": characteristics
    }


# ============================================================
# Block 5: Optional Header
# ============================================================

def parse_optional_header(data, coff_header):
    """
    Parses important fields from the Optional Header.

    Also locates:
        Export Directory
        Import Directory
    """

    coff_offset = coff_header["offset"]
    opt_size = coff_header["size_of_optional_header"]

    optional_offset = coff_offset + 20

    if optional_offset + opt_size > len(data):
        print("Error: Invalid Optional Header.")
        return None

    magic = struct.unpack_from(
        "<H",
        data,
        optional_offset
    )[0]

    major_linker_version = struct.unpack_from(
        "<B",
        data,
        optional_offset + 2
    )[0]

    minor_linker_version = struct.unpack_from(
        "<B",
        data,
        optional_offset + 3
    )[0]

    size_of_code = struct.unpack_from(
        "<I",
        data,
        optional_offset + 4
    )[0]

    size_of_initialized_data = struct.unpack_from(
        "<I",
        data,
        optional_offset + 8
    )[0]

    size_of_uninitialized_data = struct.unpack_from(
        "<I",
        data,
        optional_offset + 12
    )[0]

    address_of_entry_point = struct.unpack_from(
        "<I",
        data,
        optional_offset + 16
    )[0]

    base_of_code = struct.unpack_from(
        "<I",
        data,
        optional_offset + 20
    )[0]

    # --------------------------------------------------------
    # PE32
    # --------------------------------------------------------

    if magic == 0x10B:

        architecture = "PE32 (32-bit)"

        base_of_data = struct.unpack_from(
            "<I",
            data,
            optional_offset + 24
        )[0]

        image_base = struct.unpack_from(
            "<I",
            data,
            optional_offset + 28
        )[0]

        data_directory_offset = (
            optional_offset + 0x60
        )

    # --------------------------------------------------------
    # PE32+
    # --------------------------------------------------------

    elif magic == 0x20B:

        architecture = "PE32+ (64-bit)"

        base_of_data = None

        image_base = struct.unpack_from(
            "<Q",
            data,
            optional_offset + 24
        )[0]

        data_directory_offset = (
            optional_offset + 0x70
        )

    else:
        print(
            f"Error: Unknown Optional Header magic "
            f"0x{magic:X}."
        )
        return None

    # Need enough bytes for at least Export + Import entries
    if data_directory_offset + 16 > len(data):
        print("Error: Invalid Data Directory.")
        return None

    # --------------------------------------------------------
    # Data Directory Entry 0: Export Directory
    # --------------------------------------------------------

    (
        export_directory_rva,
        export_size
    ) = struct.unpack_from(
        "<II",
        data,
        data_directory_offset
    )

    # --------------------------------------------------------
    # Data Directory Entry 1: Import Directory
    # --------------------------------------------------------

    (
        import_directory_rva,
        import_size
    ) = struct.unpack_from(
        "<II",
        data,
        data_directory_offset + 8
    )

    return {
        "offset": optional_offset,
        "magic": magic,
        "architecture": architecture,

        "major_linker_version": major_linker_version,
        "minor_linker_version": minor_linker_version,

        "size_of_code": size_of_code,
        "size_of_initialized_data": size_of_initialized_data,
        "size_of_uninitialized_data": size_of_uninitialized_data,

        "address_of_entry_point": address_of_entry_point,

        "base_of_code": base_of_code,
        "base_of_data": base_of_data,

        "image_base": image_base,

        "data_directory_offset": data_directory_offset,

        "export_directory_rva": export_directory_rva,
        "export_size": export_size,

        "import_directory_rva": import_directory_rva,
        "import_size": import_size
    }


# ============================================================
# Block 6: Section Headers
# ============================================================

def parse_section_headers(data, coff_header):
    """
    Parses the PE Section Table.

    Each section header is 40 bytes.
    """

    coff_offset = coff_header["offset"]

    opt_size = (
        coff_header["size_of_optional_header"]
    )

    num_sections = (
        coff_header["number_of_sections"]
    )

    section_table_offset = (
        coff_offset
        + 20
        + opt_size
    )

    sections = []

    for i in range(num_sections):

        section_offset = (
            section_table_offset
            + (i * 40)
        )

        if section_offset + 40 > len(data):
            print(
                f"Error: Invalid section header {i}."
            )
            return None

        name = (
            struct.unpack_from(
                "8s",
                data,
                section_offset
            )[0]
            .rstrip(b"\x00")
            .decode(
                "utf-8",
                errors="replace"
            )
        )

        virtual_size = struct.unpack_from(
            "<I",
            data,
            section_offset + 8
        )[0]

        virtual_address = struct.unpack_from(
            "<I",
            data,
            section_offset + 12
        )[0]

        size_of_raw_data = struct.unpack_from(
            "<I",
            data,
            section_offset + 16
        )[0]

        pointer_to_raw_data = struct.unpack_from(
            "<I",
            data,
            section_offset + 20
        )[0]

        pointer_to_relocations = struct.unpack_from(
            "<I",
            data,
            section_offset + 24
        )[0]

        pointer_to_line_numbers = struct.unpack_from(
            "<I",
            data,
            section_offset + 28
        )[0]

        number_of_relocations = struct.unpack_from(
            "<H",
            data,
            section_offset + 32
        )[0]

        number_of_line_numbers = struct.unpack_from(
            "<H",
            data,
            section_offset + 34
        )[0]

        characteristics = struct.unpack_from(
            "<I",
            data,
            section_offset + 36
        )[0]

        sections.append({
            "name": name,

            "virtual_size": virtual_size,
            "virtual_address": virtual_address,

            "size_of_raw_data": size_of_raw_data,
            "pointer_to_raw_data": pointer_to_raw_data,

            "pointer_to_relocations": pointer_to_relocations,
            "pointer_to_line_numbers": pointer_to_line_numbers,

            "number_of_relocations": number_of_relocations,
            "number_of_line_numbers": number_of_line_numbers,

            "characteristics": characteristics
        })

    return sections


# ============================================================
# Block 7: RVA -> File Offset
# ============================================================

def rva_to_file_offset(rva, sections):
    """
    Converts a Relative Virtual Address into a
    raw file offset.

    Formula:

        Raw Offset
        =
        RVA
        - Section Virtual Address
        + Section Raw Offset
    """

    for section in sections:

        virtual_address = (
            section["virtual_address"]
        )

        virtual_size = (
            section["virtual_size"]
        )

        raw_offset = (
            section["pointer_to_raw_data"]
        )

        raw_size = (
            section["size_of_raw_data"]
        )

        section_size = max(
            virtual_size,
            raw_size
        )

        if (
            virtual_address
            <= rva
            < virtual_address + section_size
        ):
            return (
                rva
                - virtual_address
                + raw_offset
            )

    return None


# ============================================================
# Block 8: Import Table
# ============================================================

def parse_imports(
    data,
    optional_header,
    sections
):
    """
    Extracts imported DLLs and imported functions.
    """

    import_rva = (
        optional_header["import_directory_rva"]
    )

    if import_rva == 0:
        return []

    import_offset = rva_to_file_offset(
        import_rva,
        sections
    )

    if import_offset is None:
        return []

    # --------------------------------------------------------
    # Determine thunk format
    # --------------------------------------------------------

    if optional_header["magic"] == 0x10B:

        thunk_format = "<I"
        thunk_size = 4

        ordinal_flag = (
            0x80000000
        )

    else:

        thunk_format = "<Q"
        thunk_size = 8

        ordinal_flag = (
            0x8000000000000000
        )

    imports = []

    descriptor_offset = import_offset

    # --------------------------------------------------------
    # Walk IMAGE_IMPORT_DESCRIPTOR array
    # --------------------------------------------------------

    while True:

        if descriptor_offset + 20 > len(data):
            break

        (
            original_first_thunk,
            time_date_stamp,
            forwarder_chain,
            name_rva,
            first_thunk
        ) = struct.unpack_from(
            "<IIIII",
            data,
            descriptor_offset
        )

        # All-zero descriptor = end
        if not any([
            original_first_thunk,
            time_date_stamp,
            forwarder_chain,
            name_rva,
            first_thunk
        ]):
            break

        # ----------------------------------------------------
        # DLL Name
        # ----------------------------------------------------

        name_offset = rva_to_file_offset(
            name_rva,
            sections
        )

        if name_offset is None:
            break

        name_end = data.find(
            b"\x00",
            name_offset
        )

        if name_end == -1:
            break

        dll_name = data[
            name_offset:name_end
        ].decode(
            "ascii",
            errors="replace"
        )

        functions = []

        # ----------------------------------------------------
        # Thunk Table
        # ----------------------------------------------------

        thunk_rva = original_first_thunk

        # Some binaries omit OriginalFirstThunk
        if thunk_rva == 0:
            thunk_rva = first_thunk

        thunk_offset = rva_to_file_offset(
            thunk_rva,
            sections
        )

        if thunk_offset is not None:

            while True:

                if (
                    thunk_offset
                    + thunk_size
                    > len(data)
                ):
                    break

                thunk_value = struct.unpack_from(
                    thunk_format,
                    data,
                    thunk_offset
                )[0]

                if thunk_value == 0:
                    break

                # --------------------------------------------
                # Import by ordinal
                # --------------------------------------------

                if thunk_value & ordinal_flag:

                    ordinal = (
                        thunk_value
                        & 0xFFFF
                    )

                    functions.append(
                        f"Ordinal {ordinal}"
                    )

                # --------------------------------------------
                # Import by name
                # --------------------------------------------

                else:

                    import_name_offset = (
                        rva_to_file_offset(
                            thunk_value,
                            sections
                        )
                    )

                    if import_name_offset is None:
                        break

                    # IMAGE_IMPORT_BY_NAME:
                    #
                    # WORD Hint
                    # CHAR Name[]
                    #
                    # Skip the 2-byte Hint
                    function_name_offset = (
                        import_name_offset + 2
                    )

                    function_end = data.find(
                        b"\x00",
                        function_name_offset
                    )

                    if function_end == -1:
                        break

                    function_name = data[
                        function_name_offset:
                        function_end
                    ].decode(
                        "ascii",
                        errors="replace"
                    )

                    functions.append(
                        function_name
                    )

                thunk_offset += thunk_size

        imports.append({
            "dll": dll_name,
            "functions": functions
        })

        descriptor_offset += 20

    return imports


# ============================================================
# Block 9: Export Table
# ============================================================

def parse_exports(
    data,
    optional_header,
    sections
):
    """
    Extracts named functions exported by a PE.

    Particularly useful for DLL files.
    """

    export_rva = (
        optional_header["export_directory_rva"]
    )

    if export_rva == 0:
        return []

    export_offset = rva_to_file_offset(
        export_rva,
        sections
    )

    if export_offset is None:
        return []

    if export_offset + 40 > len(data):
        return []

    # IMAGE_EXPORT_DIRECTORY = 40 bytes
    (
        characteristics,
        time_date_stamp,
        major_version,
        minor_version,
        dll_name_rva,
        ordinal_base,
        number_of_functions,
        number_of_names,
        address_of_functions_rva,
        address_of_names_rva,
        address_of_name_ordinals_rva
    ) = struct.unpack_from(
        "<IIHHIIIIIII",
        data,
        export_offset
    )

    # --------------------------------------------------------
    # Convert table RVAs to file offsets
    # --------------------------------------------------------

    names_offset = rva_to_file_offset(
        address_of_names_rva,
        sections
    )

    ordinals_offset = rva_to_file_offset(
        address_of_name_ordinals_rva,
        sections
    )

    functions_offset = rva_to_file_offset(
        address_of_functions_rva,
        sections
    )

    if (
        names_offset is None
        or ordinals_offset is None
        or functions_offset is None
    ):
        return []

    exports = []

    # --------------------------------------------------------
    # Walk named exports
    # --------------------------------------------------------

    for i in range(number_of_names):

        # Each name-table entry is a 4-byte RVA
        function_name_rva = struct.unpack_from(
            "<I",
            data,
            names_offset + (i * 4)
        )[0]

        function_name_offset = (
            rva_to_file_offset(
                function_name_rva,
                sections
            )
        )

        if function_name_offset is None:
            continue

        name_end = data.find(
            b"\x00",
            function_name_offset
        )

        if name_end == -1:
            continue

        function_name = data[
            function_name_offset:
            name_end
        ].decode(
            "ascii",
            errors="replace"
        )

        # Ordinal table contains 2-byte indexes
        ordinal_index = struct.unpack_from(
            "<H",
            data,
            ordinals_offset + (i * 2)
        )[0]

        # Function Address Table contains 4-byte RVAs
        function_rva = struct.unpack_from(
            "<I",
            data,
            functions_offset
            + (ordinal_index * 4)
        )[0]

        ordinal = (
            ordinal_base
            + ordinal_index
        )

        function_offset = (
            rva_to_file_offset(
                function_rva,
                sections
            )
        )

        exports.append({
            "name": function_name,
            "ordinal": ordinal,
            "rva": function_rva,
            "file_offset": function_offset
        })

    return exports


# ============================================================
# Block 10: Display Results
# ============================================================

def display_pe_info(
    file_path,
    dos,
    pe_signature,
    coff,
    optional,
    sections,
    imports,
    exports
):

    print()
    print(f"File: {file_path}")
    print()

    # --------------------------------------------------------
    # DOS
    # --------------------------------------------------------

    print("=== DOS HEADER ===")

    print(
        f"Signature: "
        f"{dos['magic'].decode()}"
    )

    print(
        f"e_lfanew: "
        f"0x{dos['e_lfanew']:X}"
    )

    print()

    # --------------------------------------------------------
    # PE
    # --------------------------------------------------------

    print("=== PE HEADER ===")

    print(
        f"Signature: "
        f"{pe_signature}"
    )

    print()

    # --------------------------------------------------------
    # COFF
    # --------------------------------------------------------

    print("=== COFF HEADER ===")

    print(
        f"Machine: "
        f"0x{coff['machine']:04X}"
    )

    print(
        f"Number of Sections: "
        f"{coff['number_of_sections']}"
    )

    print(
        f"Optional Header Size: "
        f"{coff['size_of_optional_header']}"
    )

    print(
        f"Characteristics: "
        f"0x{coff['characteristics']:04X}"
    )

    print()

    # --------------------------------------------------------
    # Optional Header
    # --------------------------------------------------------

    print("=== OPTIONAL HEADER ===")

    print(
        f"Type: "
        f"{optional['architecture']}"
    )

    print(
        f"Magic: "
        f"0x{optional['magic']:04X}"
    )

    print(
        f"Entry Point RVA: "
        f"0x{optional['address_of_entry_point']:X}"
    )

    print(
        f"Image Base: "
        f"0x{optional['image_base']:X}"
    )

    entry_va = (
        optional["image_base"]
        + optional["address_of_entry_point"]
    )

    print(
        f"Preferred Entry Point VA: "
        f"0x{entry_va:X}"
    )

    print(
        f"Import Directory RVA: "
        f"0x{optional['import_directory_rva']:X}"
    )

    print(
        f"Export Directory RVA: "
        f"0x{optional['export_directory_rva']:X}"
    )

    print()

    # --------------------------------------------------------
    # Sections
    # --------------------------------------------------------

    print("=== SECTIONS ===")

    for section in sections:

        print(section["name"])

        print(
            f"  Virtual Address : "
            f"0x{section['virtual_address']:X}"
        )

        print(
            f"  Virtual Size    : "
            f"0x{section['virtual_size']:X}"
        )

        print(
            f"  Raw Offset      : "
            f"0x{section['pointer_to_raw_data']:X}"
        )

        print(
            f"  Raw Size        : "
            f"0x{section['size_of_raw_data']:X}"
        )

        print()

    # --------------------------------------------------------
    # Imports
    # --------------------------------------------------------

    print("=== IMPORTS ===")

    if not imports:

        print("No imports found.")

    else:

        for imported_dll in imports:

            print(
                f"{imported_dll['dll']}:"
            )

            for function in (
                imported_dll["functions"]
            ):
                print(
                    f"  {function}"
                )

            print()

    # --------------------------------------------------------
    # Exports
    # --------------------------------------------------------

    print("=== EXPORTS ===")

    if not exports:

        print("No named exports found.")

    else:

        for export in exports:

            offset = export["file_offset"]

            if offset is None:
                offset_text = "N/A"
            else:
                offset_text = (
                    f"0x{offset:X}"
                )

            print(
                f"{export['name']}"
                f" | Ordinal {export['ordinal']}"
                f" | RVA 0x{export['rva']:X}"
                f" | File Offset {offset_text}"
            )


# ============================================================
# Block 11: Main PE Parser
# ============================================================

def parse_pe_file(file_path):

    data = read_pe_file(file_path)

    if data is None:
        return

    dos = parse_dos_header(data)

    if dos is None:
        return

    pe_signature = parse_pe_signature(
        data,
        dos["e_lfanew"]
    )

    if pe_signature is None:
        return

    coff = parse_coff_header(
        data,
        dos["e_lfanew"]
    )

    if coff is None:
        return

    optional = parse_optional_header(
        data,
        coff
    )

    if optional is None:
        return

    sections = parse_section_headers(
        data,
        coff
    )

    if sections is None:
        return

    imports = parse_imports(
        data,
        optional,
        sections
    )

    exports = parse_exports(
        data,
        optional,
        sections
    )

    display_pe_info(
        file_path,
        dos,
        pe_signature,
        coff,
        optional,
        sections,
        imports,
        exports
    )


# ============================================================
# Program Entry Point
# ============================================================

if __name__ == "__main__":

    if len(sys.argv) != 2:

        print(
            "Usage: "
            "python pe_parser.py <file.exe|file.dll>"
        )

        sys.exit(1)

    parse_pe_file(
        sys.argv[1]
    )