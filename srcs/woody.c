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


unsigned char buffer[BUFFER_SIZE];

STATUS checkELF(const char *filename, const packer *packer_t)
{
	packer *pak = (packer *)packer_t;
	LOG_OK("Checking ELF...");

	// Vérification du 64bit
	fread(&pak->header, sizeof(pak->header), 1, pak->binary);
	if ((memcmp(pak->header.e_ident, ELFMAG, SELFMAG) != 0) ||
		(pak->header.e_ident[EI_CLASS] != ELFCLASS64) /* || (pak->header.e_machine != EM_X86_64) */ )
	{
		LOG_ERROR("Le fichier %s n'est pas un binaire ELF 64-bit", filename);
		return ERR_NOTELF;
	}

	fseek(pak->binary, 0, SEEK_SET);
	return ERR_OK;
}

static void compute_md5_from_file(FILE *file, unsigned char *digest) {
    size_t bytes_read;
    unsigned int md_len;
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();

    EVP_DigestInit_ex(mdctx, EVP_md5(), NULL);

    while ((bytes_read = fread(buffer, 1, sizeof(buffer), file)) > 0)
        EVP_DigestUpdate(mdctx, buffer, bytes_read);

    EVP_DigestFinal_ex(mdctx, digest, &md_len);
    EVP_MD_CTX_free(mdctx);
}

STATUS get_bin_checksum(const packer *paker_t)
{
	packer *pak = (packer *)paker_t;
	rewind(pak->file);
	LOG_OK("Getting checksum...");

	compute_md5_from_file(pak->file, pak->checksum);
	rewind(pak->file);

	LOG_OK("Checksum: %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
		pak->checksum[0], pak->checksum[1], pak->checksum[2], pak->checksum[3],
		pak->checksum[4], pak->checksum[5], pak->checksum[6], pak->checksum[7],
		pak->checksum[8], pak->checksum[9], pak->checksum[10], pak->checksum[11],
		pak->checksum[12], pak->checksum[13], pak->checksum[14], pak->checksum[15]);

	return ERR_OK;
}

STATUS encrypt_decrypt(const void *file, const size_t len, const char *key, void *result)
{
	LOG_OK("Encrypt/Decrypt binary...");
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

STATUS output_elf(const packer *packer_t)
{
	packer *pak = (packer *)packer_t;
	LOG_OK("Generating executable.");

	pak->write_stub(pak);
	fclose(pak->binary);
	fclose(pak->file);
	if (chmod("./woody", 0755) != 0)
		LOG_ERROR("Erreur lors de la modification des permissions du fichier");
	return ERR_OK;
}

STATUS open_file(const char *filename, const packer *packer_t)
{
	size_t size_buf;
	packer *pak = (packer *)packer_t;

	LOG_OK("Opening file...");
	pak->file = fopen(filename, "rb");
	if (pak->file == NULL) {
		LOG_ERROR("Erreur lors de l'ouverture du fichier %s: %s", filename, strerror(errno));
		return ERR_ARGS;
	}

	// Get file size
	fseek(pak->file, 0, SEEK_END);
	pak->filesize = ftell(pak->file);
	rewind(pak->file);

	LOG_OK("File size: %ld", pak->filesize);

	pak->binary = fopen("./woody", "wb+");

	rewind(pak->binary);
	do {
		size_buf = fread(buffer, 1, BUFFER_SIZE, pak->file);
		fwrite(buffer, 1, size_buf, pak->binary);
	} while (size_buf > 0);
	fseek(pak->binary, 0, SEEK_SET);

	pak->check_file(filename, packer_t);
	pak->original_entry = pak->header.e_entry;
	pak->header.e_entry = pak->filesize + STUB_OFFSET;
	pak->stub_variables = (var_stub *)&stub_bin[stub_bin_len - sizeof(var_stub)];

	fwrite(&pak->header, sizeof(pak->header), 1, pak->binary);

	return ERR_OK;
}

STATUS write_stub(const packer *packer_t)
{
	packer *pak = (packer *)packer_t;
	pak->stub_variables->old_entry = pak->original_entry;
	pak->stub_variables->to_sub = pak->filesize + STUB_OFFSET;

	LOG_OK("Ecriture du stub");
	memcpy(&stub_bin[stub_bin_len - sizeof(var_stub)], pak->stub_variables, sizeof(var_stub));
	fseek(pak->binary, 0, SEEK_END);
	fwrite(stub_bin, stub_bin_len, 1, pak->binary);

	return ERR_OK;
}

STATUS set_function(packer *pak)
{
	LOG_OK("Création de la structure");
	pak->check_file = checkELF;
	pak->get_checksum = get_bin_checksum;
	pak->encrypt = encrypt_decrypt;
	pak->decrypt = encrypt_decrypt;
	pak->pack = NULL;
	pak->create_elf = output_elf;
	pak->open_file = open_file;
	pak->write_stub = write_stub;
	return ERR_OK;
}

int main(int argc, char **argv)
{
	packer	this;
	set_function(&this);

	// Check si un fichier est bien passé en argument
	if (argc != 2) {
		LOG_ERROR("Utilisation: %s <Binaire ELF64>", argv[0]);
		return ERR_ARGS;
	}

	// Open and check input file
	if (this.open_file(argv[1], &this) != ERR_OK)
		return ERR_ARGS;

	this.get_checksum(&this);

	// Modification des segments PT_NOTE en PT_LOAD
	fseek(this.binary, this.header.e_phoff, SEEK_SET);
	int idx = 0;
	while (idx++ < this.header.e_phnum) {
		Elf64_Phdr pheader;
		fread(&pheader, sizeof(pheader), 1, this.binary);
		switch (pheader.p_type) {
			case PT_NOTE:
				// LOG_OK("this.header.e_phoff + ((idx - 1) * sizeof(Elf64_Phdr)): %lx", this.header.e_phoff + ((idx - 1) * sizeof(Elf64_Phdr)));
				fseek(this.binary, this.header.e_phoff + ((idx - 1) * sizeof(Elf64_Phdr)), SEEK_SET);

				pheader.p_type = PT_LOAD;
				pheader.p_flags = PF_R | PF_X;
				pheader.p_offset = this.filesize;
				pheader.p_vaddr = this.filesize + STUB_OFFSET;
				pheader.p_paddr = this.filesize + STUB_OFFSET;
				pheader.p_filesz = stub_bin_len;
				pheader.p_memsz = stub_bin_len;

				fwrite(&pheader, sizeof(pheader), 1, this.binary);

				fseek(this.binary, this.header.e_phoff + ((idx - 1) * sizeof(Elf64_Phdr)), SEEK_SET);
				fread(&pheader, sizeof(pheader), 1, this.binary);
				LOG_OK("Segment PT_NOTE modifié");
				LOG_DEBUG("Offset fichier : 0x%lx", pheader.p_offset);
				LOG_DEBUG("Adresse Virtuelle : 0x%lx", pheader.p_vaddr);
				LOG_DEBUG("Adresse Phy : 0x%lx", pheader.p_paddr);
				LOG_DEBUG("Taille en mémoire : %lu octets", pheader.p_memsz);
				LOG_DEBUG("Size : %d", this.header.e_phentsize);
				LOG_DEBUG("Flags : %c%c%c",
					(pheader.p_flags & PF_R) ? 'R' : '-',
					(pheader.p_flags & PF_W) ? 'W' : '-',
					(pheader.p_flags & PF_X) ? 'X' : '-');
				goto next;
				//this.encrypt(&this);
			default:
				continue;
		}
	}

	LOG_ERROR("Aucune PT_NOTE trouvée, le packer s'arrête");
	return ERR_NOTARGET;

// encrypte le binaire
next:
	Elf64_Shdr sh_tab;
	char name_buffer[64];
	fseek(this.binary, this.header.e_shoff + (this.header.e_shstrndx * this.header.e_shentsize), SEEK_SET);
	fread(&sh_tab, sizeof(Elf64_Shdr), 1, this.binary);
	// printf("This: %lx\n", ftell(this.binary));
	idx = 0;
	while (idx++ < this.header.e_shnum) {
		Elf64_Shdr shdr;

		fseek(this.binary, this.header.e_shoff + (idx * this.header.e_shentsize), SEEK_SET);
		fread(&shdr, sizeof(Elf64_Shdr), 1, this.binary);
		fseek(this.binary, sh_tab.sh_offset + shdr.sh_name, SEEK_SET);
		fread(name_buffer, 1, sizeof(name_buffer) - 1, this.binary);
		name_buffer[sizeof(name_buffer) - 1] = '\0';
		if (strcmp(name_buffer, ".woody") == 0) {
			LOG_ERROR("Ce binaire est déjà packer par woody_woodpacker");
			return ERR_NOTELF;
		}
		else if (strcmp(name_buffer, ".text") == 0) {
			LOG_OK("Section .text trouvée");

			fseek(this.binary, sh_tab.sh_offset + shdr.sh_name, SEEK_SET);
			const char *new_name = ".woody";
			fwrite(new_name, strlen(new_name) + 1, 1, this.binary);
			LOG_OK("Section .text renommée en .woody avec succès.");
			LOG_DEBUG("sh_tab.sh_offset: 0x%lx", shdr.sh_offset);
			LOG_DEBUG("sh_tab.sh_name: 0x%x", shdr.sh_name);
			LOG_DEBUG("shdr.sh_addr: 0x%lx", shdr.sh_addr);
			LOG_DEBUG("fin: 0x%lx", shdr.sh_size);
			fseek(this.file, shdr.sh_offset, SEEK_SET);
			fseek(this.binary, shdr.sh_offset, SEEK_SET);
			LOG_DEBUG("XOR: %x", (char)this.original_entry);
			LOG_OK("Ecryption de la section .text");
			char *encryption_buffer = (char *) calloc(shdr.sh_size + 1, sizeof(char));
			if (fread(encryption_buffer, 1, shdr.sh_size, this.file) != shdr.sh_size) {
				LOG_ERROR("Erreur lors de la lecture de la section");
				free(encryption_buffer);
				return ERR_NOTARGET;
			}
			for (size_t i = 0; i < shdr.sh_size; i++)
				encryption_buffer[i] ^= (char)(this.original_entry & 0xFF);
			fwrite(encryption_buffer, 1, shdr.sh_size, this.binary);
			free(encryption_buffer);
			this.stub_variables->text_addr = shdr.sh_addr;
			this.stub_variables->text_size = shdr.sh_size;
			this.stub_variables->xor_key = (char) this.original_entry;
			break;
		}
	}

	// Set header, make stub, set new file executable and close all files.
	this.create_elf(&this);
	return 0;
}
