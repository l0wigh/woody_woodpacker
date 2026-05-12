// Fonction autorisées
// open, close, exit
// fputs, fflush, lseek
// mmap, munmap, mprotect
// perror, stderror
// syscall
// printf, fprintf, ...
// libft -> read, write, malloc, free, ...

// Notre programme doit fonctionner uniquement sur des ELF 64bit
// -> refuser les binaires non 64bits

// Le fichier encrypter doit se nommer woody

// Encryption libre
// -> xor ? (peut-être trop simple), ChaCha20 ?

// ...WOODY... <- Au début du programme encrypté

#include "woody.h"
#include <elf.h>

int main(int argc, char **argv)
{
	FILE *elf_bin_file;
	Elf64_Ehdr header;
	WoodyInfos winfo;
	int idx;

	// Check si un fichier est bien passé en argument
	if (argc != 2)
	{
		printf("Usage: %s <ELF64 binary to pack>", argv[0]);
		return ERR_ARGS;
	}

	// Ouverture du fichier et vérification d'erreur
	elf_bin_file = fopen(argv[1], "rb");
	if (elf_bin_file == NULL)
	{
		printf("Error while opening %s: %s", argv[1], strerror(errno));
		return errno;
	}

	// Vérification du 64bit
	fread(&header, sizeof(header), 1, elf_bin_file);
	if ((memcmp(header.e_ident, ELFMAG, SELFMAG) != 0) ||
		(header.e_ident[EI_CLASS] != ELFCLASS64))
	{
		printf("Not a valid ELF64 file\n");
		return ERR_NOTELF;
	}

	// Sauvegarde de l'entry point d'origine pour créer le jump après
	winfo.original_entry = header.e_entry;
	printf("Original Entry: %ld\n", winfo.original_entry);

	// Recherche du PT_NOTE
	fseek(elf_bin_file, header.e_phoff, SEEK_SET);
	idx = 0;
	while (idx++ < header.e_phnum)
	{
		Elf64_Phdr pheader;
		fread(&pheader, sizeof(pheader), 1, elf_bin_file);
		switch (pheader.p_type)
		{
			case PT_NOTE:
				printf("Segment PT_NOTE [%d] trouvé :\n", idx);
				printf("  - Offset fichier : 0x%lx\n", pheader.p_offset);
				printf("  - Adresse Virtuelle : 0x%lx\n", pheader.p_vaddr);
				printf("  - Taille en mémoire : %lu octets\n", pheader.p_memsz);
				printf("  - Flags : %c%c%c\n",
					(pheader.p_flags & PF_R) ? 'R' : '-',
					(pheader.p_flags & PF_W) ? 'W' : '-',
					(pheader.p_flags & PF_X) ? 'X' : '-');
				break;
			case PT_LOAD:
				printf("Segment PT_LOAD [%d] trouvé :\n", idx);
				printf("  - Offset fichier : 0x%lx\n", pheader.p_offset);
				printf("  - Adresse Virtuelle : 0x%lx\n", pheader.p_vaddr);
				printf("  - Taille en mémoire : %lu octets\n", pheader.p_memsz);
				printf("  - Flags : %c%c%c\n",
					(pheader.p_flags & PF_R) ? 'R' : '-',
					(pheader.p_flags & PF_W) ? 'W' : '-',
					(pheader.p_flags & PF_X) ? 'X' : '-');
				break;
			default:
				continue;
		}
	}

	fclose(elf_bin_file);
	return 0;
}
