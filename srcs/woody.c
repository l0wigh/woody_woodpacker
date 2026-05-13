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
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "stub.h"


STATUS checkELF(const packer *pak)
{
	(void)pak;
	LOG_INFO("Checking ELF...");
	return ERR_OK;
}

STATUS get_bin_checksum(const packer *pak)
{
	(void)pak;
	LOG_INFO("Getting checksum...");
	return ERR_OK;
}

STATUS encrypt_decrypt(const void *file, const size_t len, const char *key, void *result)
{
	LOG_INFO("Encrypt/Decrypt binary...");
	if (!key)
		return ERR_NOKEY;
	if (!result)
		return ERR_NOTARGET;

	uint8_t *output = (uint8_t *)result;
	int keyLen = strlen(key);

	for (size_t i = 0; i < len; i++)
		output[i] =((uint8_t *)file)[i] ^ (uint8_t)key[i % keyLen];

	LOG_OK("Encrypt/Decrypt finish.");
	return ERR_OK;
}

STATUS output_elf(const packer *pak)
{
	(void)pak;
	LOG_INFO("Generating executable.");
	return ERR_OK;
}

STATUS set_function(packer *pak)
{
	(void)pak;
	LOG_INFO("Setting structure...");
	pak->check_file = checkELF;
	pak->get_checksum = get_bin_checksum;
	pak->encrypt = encrypt_decrypt;
	pak->decrypt = encrypt_decrypt;
	pak->pack = NULL;
	pak->unpack = NULL;
	pak->create_elf = output_elf;
	return ERR_OK;
}

int main(int argc, char **argv)
{
	packer	this;
	set_function(&this);
	size_t size_buf;
	char buffer[BUFFER_SIZE];
	var_stub *stub_variables;

	// Check si un fichier est bien passé en argument
	if (argc != 2)
	{
		LOG_ERROR("Usage: %s <ELF64 binary to pack>", argv[0]);
		return ERR_ARGS;
	}

	// Ouverture du fichier et vérification d'erreur
	LOG_INFO("Opening binary file.");
	this.file = fopen(argv[1], "rb");
	if (this.file == NULL)
	{
		LOG_ERROR("Error while opening %s: %s", argv[1], strerror(errno));
		return errno;
	}

	fseek(this.file, 0, SEEK_END);
	this.filesize = ftell(this.file);
	fseek(this.file, 0, SEEK_SET);

	this.binary = fopen("./woody", "wb+");

	fseek(this.binary, 0, SEEK_SET);
	do {
		size_buf = fread(buffer, 1, BUFFER_SIZE, this.file);
		fwrite(buffer, 1, size_buf, this.binary);
	} while (size_buf > 0);
	fseek(this.binary, 0, SEEK_SET);

	// Vérification du 64bit
	fread(&this.header, sizeof(this.header), 1, this.binary);
	if ((memcmp(this.header.e_ident, ELFMAG, SELFMAG) != 0) ||
		(this.header.e_ident[EI_CLASS] != ELFCLASS64) /* || (this.header.e_machine != EM_X86_64) */ )
	{
		return ERR_NOTELF;
	}

	fseek(this.binary, 0, SEEK_SET);
	this.original_entry = this.header.e_entry;
	this.header.e_entry = this.filesize + 0xc0000000;
//	memcpy(&stub_bin[79], &this.original_entry, sizeof(Elf64_Addr));
//	memcpy(&stub_bin[87], &this.header.e_entry, sizeof(Elf64_Addr));

	stub_variables = (var_stub *)&stub_bin[stub_bin_len - sizeof(var_stub)];
	stub_variables->old_entry = this.original_entry;
	stub_variables->to_sub = this.filesize + 0xc0000000;
	memcpy(&stub_bin[stub_bin_len - sizeof(var_stub)], stub_variables, sizeof(var_stub));

	fwrite(&this.header, sizeof(this.header), 1, this.binary);

	LOG_INFO("Payload (%u bytes):\n", stub_bin_len);
    for (size_t i = 0; i < stub_bin_len; i++) {
        printf("0x%02x, ", stub_bin[i]);
        if ((i + 1) % 12 == 0) printf("\n");
    }
    printf("\n\n");

	fseek(this.binary, this.header.e_phoff, SEEK_SET);
	int idx = 0;
	while (idx++ < this.header.e_phnum)
	{
		Elf64_Phdr pheader;
		fread(&pheader, sizeof(pheader), 1, this.binary);
		switch (pheader.p_type)
		{
			case PT_NOTE:
				// LOG_INFO("this.header.e_phoff + ((idx - 1) * sizeof(Elf64_Phdr)): %lx", this.header.e_phoff + ((idx - 1) * sizeof(Elf64_Phdr)));
				fseek(this.binary, this.header.e_phoff + ((idx - 1) * sizeof(Elf64_Phdr)), SEEK_SET);

				pheader.p_type = PT_LOAD;
				pheader.p_flags = PF_R | PF_X;
				pheader.p_offset = this.filesize;
				pheader.p_vaddr = this.filesize + 0xc0000000;
				// pheader.p_paddr = ;
				pheader.p_filesz = stub_bin_len;
				pheader.p_memsz = stub_bin_len;

				fwrite(&pheader, sizeof(pheader), 1, this.binary);

				fseek(this.binary, this.header.e_phoff + ((idx - 1) * sizeof(Elf64_Phdr)), SEEK_SET);
				fread(&pheader, sizeof(pheader), 1, this.binary);
				LOG_DEBUG("Segment [%d] trouvé :", idx);
				LOG_DEBUG("  - Offset fichier : 0x%lx", pheader.p_offset);
				LOG_DEBUG("  - Adresse Virtuelle : 0x%lx", pheader.p_vaddr);
				LOG_DEBUG("  - Adresse Phy : 0x%lx", pheader.p_paddr);
				LOG_DEBUG("  - Taille en mémoire : %lu octets", pheader.p_memsz);
				LOG_DEBUG("  - Size : %d", this.header.e_phentsize);
				LOG_DEBUG("  - filesize: %lu", pheader.p_filesz);
				LOG_DEBUG("  - palign: %lu", pheader.p_align);
				LOG_DEBUG("  - Flags : %c%c%c",
					(pheader.p_flags & PF_R) ? 'R' : '-',
					(pheader.p_flags & PF_W) ? 'W' : '-',
					(pheader.p_flags & PF_X) ? 'X' : '-');
				goto next;
			default:
				continue;
		}
	}

next:
	Elf64_Shdr sh_tab;
	char name_buffer[64];
	fseek(this.binary, this.header.e_shoff + (this.header.e_shstrndx * this.header.e_shentsize), SEEK_SET);
	fread(&sh_tab, sizeof(Elf64_Shdr), 1, this.binary);
	printf("This: %lx\n", ftell(this.binary));
	idx = 0;
	while (idx++ < this.header.e_shnum)
	{
		Elf64_Shdr shdr;

		fseek(this.binary, this.header.e_shoff + (idx * this.header.e_shentsize), SEEK_SET);
		fread(&shdr, sizeof(Elf64_Shdr), 1, this.binary);
		fseek(this.binary, sh_tab.sh_offset + shdr.sh_name, SEEK_SET);
		fread(name_buffer, 1, sizeof(name_buffer) - 1, this.binary);
		name_buffer[sizeof(name_buffer) - 1] = '\0';
		if (strcmp(name_buffer, ".text") == 0)
		{
			printf("sh_tab.sh_offset: %lx\n", shdr.sh_offset);
			printf("sh_tab.sh_name: %x\n", shdr.sh_name);
			printf("shdr.sh_addr: %lx\n", shdr.sh_addr);
			printf("fin: %lx", shdr.sh_size);
			fseek(this.file, shdr.sh_offset, SEEK_SET);
			fseek(this.binary, shdr.sh_offset, SEEK_SET);
			size_t i = 0;
			printf("XOR: %x\n", (char)this.original_entry);
			for (; i < shdr.sh_size; i = i + BUFFER_SIZE)
			{
				fread(&buffer, BUFFER_SIZE, 1, this.file);
				for (size_t j = 0; j < BUFFER_SIZE; j++)
					buffer[j] ^= (char) this.original_entry;
				fwrite(buffer, BUFFER_SIZE, 1, this.binary);
			}
			if (i < shdr.sh_size)
			{
				fread(&buffer, shdr.sh_size - i, 1, this.file);
				for (size_t j = 0; j < shdr.sh_size - i; j++)
					buffer[j] = buffer[j] ^ (char) this.original_entry;
				fwrite(buffer, shdr.sh_size - i, 1, this.binary);
			}
			stub_variables->sexion = shdr.sh_addr;
			stub_variables->chibre = shdr.sh_size;
			stub_variables->chatte = (char) this.original_entry;
			fseek(this.binary, this.header.e_shoff + ((idx - 1) * this.header.e_shentsize), SEEK_SET);
		}
	}

	fseek(this.binary, 0, SEEK_END);
	fwrite(stub_bin, stub_bin_len, 1, this.binary);
	// ADD PAYLOAD;
	fclose(this.binary);
	fclose(this.file);
	return 0;
}
