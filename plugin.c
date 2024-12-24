#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

#if defined(__linux__) || defined(__CYGWIN__)
#include <endian.h>
#elif defined(__APPLE__)
#include <libkern/OSByteOrder.h>

#define htobe16(x) OSSwapHostToBigInt16(x)
#define htole16(x) OSSwapHostToLittleInt16(x)
#define be16toh(x) OSSwapBigToHostInt16(x)
#define le16toh(x) OSSwapLittleToHostInt16(x)

#define htobe32(x) OSSwapHostToBigInt32(x)
#define htole32(x) OSSwapHostToLittleInt32(x)
#define be32toh(x) OSSwapBigToHostInt32(x)
#define le32toh(x) OSSwapLittleToHostInt32(x)

#define htobe64(x) OSSwapHostToBigInt64(x)
#define htole64(x) OSSwapHostToLittleInt64(x)
#define be64toh(x) OSSwapBigToHostInt64(x)
#define le64toh(x) OSSwapLittleToHostInt64(x)
#else

#if !defined(__BYTE_ORDER__)
#error "No endian define provided by compiler"
#endif

#if (__BYTE_ORDER__ == __ORDER_BIG_ENDIAN__)

#define htobe16(x) (x)
#define htole16(x) __builtin_bswap16(x)
#define be16toh(x) (x)
#define le16toh(x) __builtin_bswap16(x)

#define htobe32(x) (x)
#define htole32(x) __builtin_bswap32(x)
#define be32toh(x) (x)
#define le32toh(x) __builtin_bswap32(x)

#define htobe64(x) (x)
#define htole64(x) __builtin_bswap64(x)
#define be64toh(x) (x)
#define le64toh(x) __builtin_bswap64(x)

#else

#define htobe16(x) __builtin_bswap16(x)
#define htole16(x) (x)
#define be16toh(x) __builtin_bswap16(x)
#define le16toh(x) (x)

#define htobe32(x) __builtin_bswap32(x)
#define htole32(x) (x)
#define be32toh(x) __builtin_bswap32(x)
#define le32toh(x) (x)

#define htobe64(x) __builtin_bswap64(x)
#define htole64(x) (x)
#define be64toh(x) __builtin_bswap64(x)
#define le64toh(x) (x)

#endif

#endif

#include <elf.h>

#define ELF32_IDENT_VALID(ehdr)            \
   ((ehdr)->e_ident[EI_MAG0] == ELFMAG0 && \
    (ehdr)->e_ident[EI_MAG1] == ELFMAG1 && \
    (ehdr)->e_ident[EI_MAG2] == ELFMAG2 && \
    (ehdr)->e_ident[EI_MAG3] == ELFMAG3)

#define ELF32_IS_32(ehdr) ((ehdr)->e_ident[EI_CLASS] == ELFCLASS32)

#define ELF32_IS_BE(ehdr) ((ehdr)->e_ident[EI_DATA] == ELFDATA2MSB)



#define GLUE2(a,b) a##b
#define GLUE(a,b) GLUE2(a,b)
#define ARRLEN(a) (sizeof(a) / sizeof((a)[0]))

#define BITSET_SIZE_BYTES(n) ((((n) + 8 * sizeof(uint64_t) - 1) & ~(8 * sizeof(uint64_t) - 1)) >> 3)
#define BITSET_ALLOC(size) calloc(1, BITSET_SIZE_BYTES(size))
#define BITSET_FREE(set) free(set)
#define BITSET_GET(set, key) ((set)[(key) >> 6] & (1 << ((key) & 63)))
#define BITSET_SET(set, key) ((set)[(key) >> 6] |= (1 << ((key) & 63)))

#define strequ(s1, s2const) (strncmp(s1, s2const, sizeof(s2const) - 1) == 0)

#include "plugin-api.h"

static struct {
    // Our state
    char                               *bss_order_string_pool;
    char                              **bss_order_strings;
    Elf32_Sym                          *bss_order_symbols;
    uint32_t                           *bss_order_symbols_found;
    size_t                              bss_order_num;
    // Our options
    char                               *order_path;
    char                               *file_path;
    // LD plugin
    int                                 api_version;
    int                                 gnu_ld_version;
    int                                 linker_output;
    const char                         *output_name;
    ld_plugin_message                   message;
    ld_plugin_add_symbols               add_symbols;
    ld_plugin_get_symbols               get_symbols;
    ld_plugin_get_symbols               get_symbols_v2;
    ld_plugin_add_input_file            add_input_file;
    ld_plugin_get_input_file            get_input_file;
    ld_plugin_register_cleanup          register_cleanup;
    ld_plugin_release_input_file        release_input_file;
    ld_plugin_register_claim_file       register_claim_file;
    ld_plugin_register_all_symbols_read register_all_symbols_read;
} pl;

#define ltell(fd) lseek((fd), 0, SEEK_CUR)

static int read_s_(int fd, void *buf, size_t nbyte, int line)
{
    ssize_t result = read(fd, buf, nbyte);
    if ((size_t)result != nbyte) {
        pl.message(LDPL_FATAL, "[%d] Could not read %lu bytes from input file [%ld]", line, nbyte, result);
        return 1;
    }
    return 0;
}
#define read_s(fd, buf, nbyte) do { if (read_s_(fd, buf, nbyte, __LINE__)) return LDPS_ERR; } while (0)

#define SEEKF(file, pos) \
    lseek((file)->fd, (file)->offset + (pos), SEEK_SET)

#define WITH_NEW_FILE_POS(file, pos)                                                                \
    for (off_t GLUE(_o_,__LINE__) = ltell((file)->fd),GLUE(_b_,__LINE__)=(SEEKF(file, pos), 1);     \
         GLUE(_b_,__LINE__);                                                                        \
         GLUE(_b_,__LINE__)=0,lseek((file)->fd, GLUE(_o_,__LINE__), SEEK_SET))

static enum ld_plugin_status
claim_file(const struct ld_plugin_input_file *file, int *claimed)
{
    *claimed = false;

    // Read the input file for COMMON symbol definitions
    // The input is assumed to be a Big-Endian 32-bit ELF file

    bool error = false;

    WITH_NEW_FILE_POS(file, 0) {
        Elf32_Ehdr ehdr;
        read_s(file->fd, &ehdr, sizeof(ehdr));

        if (!ELF32_IDENT_VALID(&ehdr) || !ELF32_IS_32(&ehdr) || !ELF32_IS_BE(&ehdr)) {
            pl.message(LDPL_FATAL, "Input file %s is not a 32-bit Big-Endian ELF file", file->name);
            return LDPS_ERR;
        }

        uint32_t e_shoff = be32toh(ehdr.e_shoff);
        uint16_t e_shentsize = be16toh(ehdr.e_shentsize);
        uint16_t e_shnum = be16toh(ehdr.e_shnum);

        if (e_shentsize != sizeof(Elf32_Shdr)) {
            pl.message(LDPL_FATAL, "e_shentsize unexpected size");
            return LDPS_ERR;
        }

        Elf32_Shdr strtab;
        char *strtab_data = NULL;
        size_t last_strtab_ind = (size_t)-1;

        // Look for symbol tables to search for COMMON symbols in
        SEEKF(file, e_shoff);
        for (size_t i = 0; i < e_shnum; i++) {
            Elf32_Shdr shdr;
            read_s(file->fd, &shdr, sizeof(shdr));

            uint32_t sh_type = be32toh(shdr.sh_type);

            if (sh_type != SHT_SYMTAB)
                continue;

            // Found a symtab
            uint32_t sh_offset = be32toh(shdr.sh_offset);
            uint32_t sh_size = be32toh(shdr.sh_size);

            // Read strtab for this symtab, cache it
            size_t strtab_ind = be32toh(shdr.sh_link);
            if (strtab_ind != last_strtab_ind) {
                if (strtab_data != NULL)
                    free(strtab_data);

                // Read strtab header
                WITH_NEW_FILE_POS(file, e_shoff + strtab_ind * sizeof(Elf32_Shdr)) {
                    read_s(file->fd, &strtab, sizeof(strtab));
                }

                // Read strtab contents
                size_t strtab_offset = be32toh(strtab.sh_offset);
                size_t strtab_size = be32toh(strtab.sh_size);
                strtab_data = malloc(strtab_size);
                WITH_NEW_FILE_POS(file, strtab_offset) {
                    read_s(file->fd, strtab_data, strtab_size);
                }

                last_strtab_ind = strtab_ind;
            }

            // Read each symbol, save the COMMON symbols into a list
            WITH_NEW_FILE_POS(file, sh_offset) {
                size_t nsym = sh_size / sizeof(Elf32_Sym);

                for (size_t j = 0; j < nsym; j++) {
                    Elf32_Sym elfsym;
                    read_s(file->fd, &elfsym, sizeof(elfsym));

                    if (be16toh(elfsym.st_shndx) != SHN_COMMON)
                        continue; // Skip non-COMMON symbols

                    const char *sym_name = &strtab_data[be32toh(elfsym.st_name)];

                    bool found = false;
                    for (size_t k = 0; k < pl.bss_order_num; k++) {
                        if (strcmp(sym_name, pl.bss_order_strings[k]) == 0) {
                            if (BITSET_GET(pl.bss_order_symbols_found, k)) {
                                // Already occupied, check equivalence
                                bool eq = (pl.bss_order_symbols[k].st_value == elfsym.st_value) &&
                                          (pl.bss_order_symbols[k].st_size == elfsym.st_size) &&
                                          (pl.bss_order_symbols[k].st_info == elfsym.st_info) &&
                                          (pl.bss_order_symbols[k].st_other == elfsym.st_other) &&
                                          (pl.bss_order_symbols[k].st_shndx == elfsym.st_shndx);
                                if (!eq) {
                                    pl.message(LDPL_ERROR, "Found distinct COMMON symbols with the same name: %s",
                                               pl.bss_order_strings[k]);
                                    error = true;
                                }
                            } else {
                                BITSET_SET(pl.bss_order_symbols_found, k);
                                pl.bss_order_symbols[k] = elfsym;
                            }
                            found = true;
                            break;
                        }
                    }
                    if (!found) {
                        pl.message(LDPL_WARNING,
                                   "Found COMMON symbol %s in input file %s not mentioned in the order spec",
                                   sym_name, file->name);
                    }
                }
            }
        }
        if (strtab_data != NULL)
            free(strtab_data);
    }
    return (error) ? LDPS_ERR : LDPS_OK;
}

static enum ld_plugin_status
all_symbols_read(void)
{
    // Make sure we got every symbol mentioned
    bool error = false;
    for (size_t i = 0; i < pl.bss_order_num; i++) {
        if (!BITSET_GET(pl.bss_order_symbols_found, i)) {
            pl.message(LDPL_ERROR, "Did not find symbol %s mentioned in the order specification in any input file",
                       pl.bss_order_strings[i]);
            error = true;
        }
    }
    if (error)
        return LDPS_ERR;

    // Create a dummy ELF file full of bss definitions generated from the COMMON defs and add it as an input file.
    // TODO look into replacing all this with pl.add_symbols? Seems like it's not possible
    // to add symbols at this stage though, since pl.add_symbols requires a file handle..

#if 0
    ELF layout:

    Elf32_Ehdr  ehdr
    char        symbol_names[sum of name lengths]
    Elf32_Sym   symbols[nsyms]
    char        section_names[sum of name lengths]
    Elf32_Shdr  NULL
    Elf32_Shdr  .bss
    Elf32_Shdr  symtab
    Elf32_Shdr  strtab
    Elf32_Shdr  shstrtab
#endif

    FILE *elf = fopen(pl.file_path, "wb");
    if (elf == NULL) {
        pl.message(LDPL_FATAL, "Could not open bss output file \"%s\" for writing", pl.file_path);
        return LDPS_ERR;
    }

    // Skip the ELF header, we'll write it at the end.
    fseek(elf, sizeof(Elf32_Ehdr), SEEK_SET);

    // First write the strtab
    uint32_t *string_offsets = malloc((2 + pl.bss_order_num) * sizeof(uint32_t));
    size_t strtab_offset = ftell(elf);
    size_t n = 0;
    string_offsets[n++] = ftell(elf);
    fprintf(elf, "%c", '\0');
    string_offsets[n++] = ftell(elf);
    fprintf(elf, "%s%c", ".bss", '\0');
    for (size_t i = 0; i < pl.bss_order_num; i++) {
        string_offsets[n++] = ftell(elf);
        fprintf(elf, "%s%c", pl.bss_order_strings[i], '\0');
    }
    size_t strtab_size = ftell(elf) - strtab_offset;

    // Align to 4 for symbols
    fwrite("\0\0\0\0", 4 - (ftell(elf) & 3), 1, elf);

    // Record greatest alignment for the overall section alignment
    size_t greatest_align = 0;

    // Now write symbols
    uint32_t symtab_offset = ftell(elf);
    n = 0;

    Elf32_Sym null_sym = {
        .st_name = htobe32(string_offsets[n++] - string_offsets[0]),
        .st_value = 0,
        .st_size = 0,
        .st_info = ELF32_ST_INFO(STB_LOCAL, STT_NOTYPE),
        .st_other = ELF32_ST_VISIBILITY(STV_DEFAULT),
        .st_shndx = htobe16(SHN_UNDEF),
    };
    fwrite(&null_sym, sizeof(null_sym), 1, elf);
    Elf32_Sym bss_sym = {
        .st_name = htobe32(string_offsets[n++] - string_offsets[0]),
        .st_value = 0,
        .st_size = 0,
        .st_info = ELF32_ST_INFO(STB_LOCAL, STT_SECTION),
        .st_other = ELF32_ST_VISIBILITY(STV_DEFAULT),
        .st_shndx = htobe16(1), /* .bss */
    };
    fwrite(&bss_sym, sizeof(bss_sym), 1, elf);

    size_t sym_offset = 0;
    for (size_t i = 0; i < pl.bss_order_num; i++) {
        Elf32_Sym *sym = &pl.bss_order_symbols[i];
        uint32_t align = be32toh(sym->st_value);
        sym_offset = (sym_offset + align - 1) & ~(align - 1);

        if (align > greatest_align)
            greatest_align = align;

        Elf32_Sym outsym = {
            .st_name = htobe32(string_offsets[n++] - string_offsets[0]),
            .st_value = htobe32(sym_offset),
            .st_size = sym->st_size,
            .st_info = sym->st_info,
            .st_other = sym->st_other,
            .st_shndx = htobe16(1), /* .bss */
        };
        fwrite(&outsym, sizeof(outsym), 1, elf);

        sym_offset += be32toh(sym->st_size);
    }
    size_t symtab_size = ftell(elf) - symtab_offset;

    free(string_offsets);

    const size_t shdr_name_offsets[5] = { 0, 1, 6, 13, 20 };
    size_t shstrtab_offset = ftell(elf);
    // Write shstrtab
    fwrite(
        /* NULL     [ 0] */ "\0"
        /* .bss     [ 1] */ ".bss\0"
        /* symtab   [ 6] */ "symtab\0"
        /* strtab   [13] */ "strtab\0"
        /* shstrtab [20] */ "shstrtab\0"
        /*          [29] */ "\0\0\0", 32, 1, elf
    );
    size_t shstrtab_size = ftell(elf) - shstrtab_offset;

    // We need: { NULL, .bss, symtab, strtab, shstrtab }
    Elf32_Shdr shdrs[5] = {
        /* NULL */ {
            .sh_name = htobe32(shdr_name_offsets[0]),
            .sh_type = htobe32(SHT_NULL),
            .sh_flags = htobe32(0),
            .sh_addr = htobe32(0x00000000),
            .sh_offset = htobe32(0x00000000),
            .sh_size = htobe32(0x00000000),
            .sh_link = htobe32(0), /* No Link */
            .sh_info = htobe32(0),
            .sh_addralign = htobe32(0),
            .sh_entsize = htobe32(0), /* Not a fixed-length array */
        },
        /* .bss */ {
            .sh_name = htobe32(shdr_name_offsets[1]),
            .sh_type = htobe32(SHT_NOBITS),
            .sh_flags = htobe32(SHF_WRITE | SHF_ALLOC),
            .sh_addr = htobe32(0x00000000),
            .sh_offset = htobe32(sizeof(Elf32_Ehdr)),
            .sh_size = htobe32(sym_offset),
            .sh_link = htobe32(0), /* No Link */
            .sh_info = htobe32(0),
            .sh_addralign = htobe32(greatest_align),
            .sh_entsize = htobe32(0), /* Not a fixed-length array */
        },
        /* symtab */ {
            .sh_name = htobe32(shdr_name_offsets[2]),
            .sh_type = htobe32(SHT_SYMTAB),
            .sh_flags = htobe32(0),
            .sh_addr = htobe32(0),
            .sh_offset = htobe32(symtab_offset),
            .sh_size = htobe32(symtab_size),
            .sh_link = htobe32(3), /* strtab */
            .sh_info = htobe32(2),
            .sh_addralign = htobe32(4),
            .sh_entsize = htobe32(sizeof(Elf32_Sym)),
        },
        /* strtab */ {
            .sh_name = htobe32(shdr_name_offsets[3]),
            .sh_type = htobe32(SHT_STRTAB),
            .sh_flags = htobe32(0),
            .sh_addr = htobe32(0),
            .sh_offset = htobe32(strtab_offset),
            .sh_size = htobe32(strtab_size),
            .sh_link = htobe32(0), /* No Link */
            .sh_info = htobe32(0),
            .sh_addralign = htobe32(1),
            .sh_entsize = htobe32(0), /* Not a fixed-length array */
        },
        /* shstrtab */ {
            .sh_name = htobe32(shdr_name_offsets[4]),
            .sh_type = htobe32(SHT_STRTAB),
            .sh_flags = htobe32(0),
            .sh_addr = htobe32(0),
            .sh_offset = htobe32(shstrtab_offset),
            .sh_size = htobe32(shstrtab_size),
            .sh_link = htobe32(0), /* No Link */
            .sh_info = htobe32(0),
            .sh_addralign = htobe32(1),
            .sh_entsize = htobe32(0), /* Not a fixed-length array */
        },
    };
    size_t shdrs_offset = ftell(elf);
    fwrite(shdrs, sizeof(shdrs), 1, elf);

    // TODO some of these fields should change based on the properties of the input files, or even better
    // it should be based on the current output format but that might not be visible to us with the limited
    // plugin api...
    Elf32_Ehdr ehdr = {
        .e_ident = {
            [EI_MAG0] = '\x7F',
            [EI_MAG1] = 'E',
            [EI_MAG2] = 'L',
            [EI_MAG3] = 'F',
            [EI_CLASS] = 0x01,
            [EI_DATA] = 0x02,
            [EI_VERSION] = 0x01,
            [EI_OSABI] = 0x00,
            [EI_ABIVERSION] = 0x00,
        },
        .e_type = htobe16(1),
        .e_machine = htobe16(8),
        .e_version = htobe32(1),
        .e_entry = htobe32(0x00000000),
        .e_phoff = htobe32(0x00000000),
        .e_shoff = htobe32(shdrs_offset),
        .e_flags = htobe32(0x20000101),
        .e_ehsize = htobe16(sizeof(Elf32_Ehdr)),
        .e_phentsize = htobe16(0x0000),
        .e_phnum = htobe16(0),
        .e_shentsize = htobe16(sizeof(Elf32_Shdr)),
        .e_shnum = htobe16(ARRLEN(shdrs)),
        .e_shstrndx = htobe16(4),
    };
    fseek(elf, 0, SEEK_SET);
    fwrite(&ehdr, sizeof(ehdr), 1, elf);

    fflush(elf);
    fclose(elf);

    // Add it as an additional input file
    enum ld_plugin_status ps = pl.add_input_file(pl.file_path);
    if (ps != LDPS_OK) {
        printf("error adding additional input file\n");
        return ps;
    }
    return LDPS_OK;
}

static enum ld_plugin_status
cleanup(void)
{
    BITSET_FREE(pl.bss_order_symbols_found);
    free(pl.bss_order_symbols);
    free(pl.bss_order_string_pool);
    free(pl.bss_order_strings);
    free(pl.order_path);
    free(pl.file_path);
    return LDPS_OK;
}

static enum ld_plugin_status
parse_option(const char *opt)
{
    if (strequ(opt, "order=")) {
        pl.order_path = strdup(opt + sizeof("order=") - 1);
        return LDPS_OK;
    }

    if (strequ(opt, "file=")) {
        pl.file_path = strdup(opt + sizeof("file=") - 1);
        return LDPS_OK;
    }

    printf("Unknown option: %s\n", opt);
    return LDPS_ERR;
}

static enum ld_plugin_status
parse_order_file(const char *order_file)
{
    // Read the entire bss order file and null-terminate it
    FILE *bss_order = fopen(order_file, "rb");
    if (bss_order == NULL) {
        pl.message(LDPL_FATAL, "Could not open bss order file %s for reading: %s", bss_order, strerror(errno));
        return LDPS_ERR;
    }

    fseek(bss_order, 0, SEEK_END);
    size_t fsize = ftell(bss_order);
    fseek(bss_order, 0, SEEK_SET);

    pl.bss_order_string_pool = malloc((fsize + 1) * sizeof(char));
    if (fread(pl.bss_order_string_pool, fsize, 1, bss_order) != 1) {
        pl.message(LDPL_FATAL, "Failed to read bss order file %s: %s", order_file, strerror(errno));
        free(pl.bss_order_string_pool);
        fclose(bss_order);
        return LDPS_ERR;
    }
    pl.bss_order_string_pool[fsize] = '\0';

    fclose(bss_order);

    // Split the file by newline to get each symbol name (TODO generalize to whitespace)

    size_t sym_count = 0;
    char *s = pl.bss_order_string_pool;
    for (size_t i = 0; i < fsize; i++, s++) {
        if (*s == '\n') {
            sym_count++;
            *s = '\0';
        }
    }

    // Get pointers to each string

    pl.bss_order_strings = malloc(sym_count * sizeof(char *));

    pl.bss_order_symbols = malloc(sym_count * sizeof(Elf32_Sym));
    pl.bss_order_symbols_found = BITSET_ALLOC(sym_count);

    bool error = false;
    s = pl.bss_order_string_pool;
    for (size_t i = 0; i < sym_count; i++) {
        pl.bss_order_strings[i] = s;

        for (size_t j = 0; j < i; j++) {
            if (strcmp(pl.bss_order_strings[j], pl.bss_order_strings[i]) == 0) {
                pl.message(LDPL_ERROR, "Duplicate name %s in symbol order file", s);
                error = true;
            }
        }

        s += strlen(s) + 1;
    }

    pl.bss_order_num = sym_count;

    return error ? LDPS_ERR : LDPS_OK;
}

enum ld_plugin_status
onload(struct ld_plugin_tv *tv)
{
    enum ld_plugin_status ps;
    bool error;

    // Initialize our state
    memset(&pl, 0, sizeof(pl));
    pl.api_version = -1;
    pl.gnu_ld_version = -1;
    pl.linker_output = -1;

    // Parse the transfer vector
    for (struct ld_plugin_tv *ptv = tv; ptv->tv_tag != LDPT_NULL; ptv++) {
        switch (ptv->tv_tag) {
            case LDPT_OPTION:
                if (ps = parse_option(ptv->tv_u.tv_string), ps != LDPS_OK)
                    return ps;
                break;

            case LDPT_MESSAGE:
                pl.message = ptv->tv_u.tv_message;
                break;

            case LDPT_API_VERSION:
                pl.api_version = ptv->tv_u.tv_val;
                break;

            case LDPT_GNU_LD_VERSION:
                pl.gnu_ld_version = ptv->tv_u.tv_val;
                break;

            case LDPT_LINKER_OUTPUT:
                pl.linker_output = ptv->tv_u.tv_val;
                break;

            case LDPT_OUTPUT_NAME:
                pl.output_name = ptv->tv_u.tv_string;
                break;

            case LDPT_REGISTER_CLAIM_FILE_HOOK:
                pl.register_claim_file = ptv->tv_u.tv_register_claim_file;
                break;

            case LDPT_REGISTER_ALL_SYMBOLS_READ_HOOK:
                pl.register_all_symbols_read = ptv->tv_u.tv_register_all_symbols_read;
                break;

            case LDPT_REGISTER_CLEANUP_HOOK:
                pl.register_cleanup = ptv->tv_u.tv_register_cleanup;
                break;

            case LDPT_ADD_SYMBOLS:
                pl.add_symbols = ptv->tv_u.tv_add_symbols;
                break;

            case LDPT_GET_INPUT_FILE:
                pl.get_input_file = ptv->tv_u.tv_get_input_file;
                break;

            case LDPT_GET_SYMBOLS:
                pl.get_symbols = ptv->tv_u.tv_get_symbols;
                break;

            case LDPT_GET_SYMBOLS_V2:
                pl.get_symbols_v2 = ptv->tv_u.tv_get_symbols;
                break;

            case LDPT_ADD_INPUT_FILE:
                pl.add_input_file = ptv->tv_u.tv_add_input_file;
                break;

            default:
                break;
        }
    }

    // Check pl.message
    if (pl.message == NULL) {
        fprintf(stderr, "No message() provided to plugin");
        return LDPS_ERR;
    }

    // Check args

    error = false;
    if (pl.order_path == NULL) {
        pl.message(LDPL_ERROR, "Missing option -plugin-opt order=<order.txt>");
        error = true;
    }
    if (pl.file_path == NULL) {
        pl.message(LDPL_ERROR, "Missing option -plugin-opt file=<bss_output_file.o>");
        error = true;
    }
    if (error)
        return LDPS_ERR;

    // Read the order file

    if (ps = parse_order_file(pl.order_path), ps != LDPS_OK)
        return ps;

    // Register callbacks

    pl.register_claim_file(claim_file);
    pl.register_all_symbols_read(all_symbols_read);
    pl.register_cleanup(cleanup);

    return LDPS_OK;
}
