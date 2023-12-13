#include <iostream>
#include <vector>
#include "file.h"
#include "aes256.h"
#include "dirent.h"

//#define DEBUG

#ifdef DEBUG
FILE* pFile;
#endif

std::vector<Packet> loadRec(const std::string path)
{
	std::vector<Packet> packetList;
	FILE* input = fopen(path.c_str(), "rb");
	BYTE version;
	fread(&version, sizeof(BYTE), 1, input);
#ifdef DEBUG
	fprintf(pFile, "version: %d\n", version);
	fflush(pFile);
#endif
	BYTE encryption;
	fread(&encryption, sizeof(BYTE), 1, input);
#ifdef DEBUG
	fprintf(pFile, "encryption: %d\n", encryption);
	fflush(pFile);
#endif
	clientVersion = GuessVersion(version, encryption);
#ifdef DEBUG
	fprintf(pFile, "clientVersion: %d\n", clientVersion);
	fflush(pFile);
#endif
	int packets;

	if (encryption == 2) {
		fread(&packets, sizeof(int), 1, input);
		packets -= 57;
#ifdef DEBUG
		fprintf(pFile, "packets: %d\n", packets);
		fflush(pFile);
#endif
		DWORD Mod = version < 4 ? 5 : version < 6 ? 8 : 6;
#ifdef DEBUG
		fprintf(pFile, "Mod: %d\n", Mod);
		fflush(pFile);
#endif

		for (DWORD i = 0; i < packets; i++) {
			uint16_t packetLength;
			fread(&packetLength, sizeof(uint16_t), 1, input);
#ifdef DEBUG
			fprintf(pFile, "packetLength: %d\n", packetLength);
			fflush(pFile);
#endif
			uint32_t timeOffset;
			fread(&timeOffset, sizeof(uint32_t), 1, input);
#ifdef DEBUG
			fprintf(pFile, "timeOffset: %d\n", timeOffset);
			fflush(pFile);
#endif

			if (!packetLength) {
				uint32_t Avail;
				fread(&Avail, sizeof(uint32_t), 1, input);
#ifdef DEBUG
				//fprintf(pFile, "Avail: %d\n", Avail);
				//fflush(pFile);
#endif
			}
			else {
				std::string packet;
				packet.resize(packetLength);
				fread(&packet[0], 1, packetLength, input);
				uint32_t Avail;
				fread(&Avail, sizeof(uint32_t), 1, input);
#ifdef DEBUG
				//fprintf(pFile, "Avail: %d\n", Avail);
				//fflush(pFile);
#endif
				BYTE Key = packetLength + timeOffset + 2;
				//fprintf(pFile, "Key 4: %d\n", packetLength + timeOffset + 2);
				//fflush(pFile);
				//fprintf(pFile, "Key 5: %d\n", Key);
				//fflush(pFile);

				for (WORD i = 0; i < packetLength; i++) {
					//fprintf(pFile, "Minus 0: %d\n", Key + 33 * i);
					//fflush(pFile);
					CHAR Minus = Key + 33 * i;
					//fprintf(pFile, "Minus 1: %d\n", Minus);
					//fflush(pFile);

					if (Minus < 0) {
						while (-Minus % Mod) Minus++;
					}
					else {
						while (Minus % Mod) Minus++;
					}

					//fprintf(pFile, "Minus 2: %d\n", Minus);
					//fflush(pFile);
					//fprintf(pFile, "Data 0: %d\n", packet[i]);
					//fflush(pFile);
					packet[i] -= Minus;
					//fprintf(pFile, "Data 1: %d\n", packet[i]);
					//fflush(pFile);
				}

				if (version > 4) {
					const char* charPacket = packet.c_str();
					//char* cPacket = (char*)charPacket;
					LPBYTE bPacket = (LPBYTE)charPacket;
					Aes256::decrypt(LPBYTE("Thy key is mine © 2006 GB Monaco"), bPacket, packetLength);
				}

				packetList.push_back(Packet(timeOffset, packet, packetLength));
			}
		}
	}
	else {
		fread(&packets, sizeof(int), 1, input);
#ifdef DEBUG
		fprintf(pFile, "packets: %d\n", packets);
		fflush(pFile);
#endif

		for (int i = 0; i < packets; i++) {
			int packetLength;
			fread(&packetLength, sizeof(int), 1, input);
#ifdef DEBUG
			fprintf(pFile, "packetLength: %d\n", packetLength);
			fflush(pFile);
#endif
			int timeOffset;
			fread(&timeOffset, sizeof(int), 1, input);
#ifdef DEBUG
			fprintf(pFile, "timeOffset: %d\n", timeOffset);
			fflush(pFile);
#endif

			if (packetLength) {
				std::string packet;
				packet.resize(packetLength);
				fread(&packet[0], 1, packetLength, input);
				packetList.push_back(Packet(timeOffset, packet, packetLength));
			}
		}
	}

	fclose(input);

#ifdef DEBUG
	fprintf(pFile, "packetList: %d\n", packetList.size());
	fflush(pFile);
#endif

	return packetList;
}

void saveByn(const std::string path, std::vector<Packet> packetList)
{
#ifdef DEBUG
	fprintf(pFile, "packetList: %d\n", packetList.size());
	fflush(pFile);
#endif

	FILE* output = fopen(path.c_str(), "wb");
	uint8_t u8 = 0x64;
	uint32_t u32 = 0;
	fwrite(&u8, sizeof(uint8_t), 1, output);
	fwrite(&clientVersion, sizeof(uint16_t), 1, output);

	for (int i = 0; i < packetList.size(); ++i) {
		u8 = 0x65;
		fwrite(&u8, sizeof(uint8_t), 1, output);

		if (i == 0) {
			fwrite(&u32, sizeof(uint32_t), 1, output);
		}
		else {
			u32 = packetList[i].timeOffset - packetList[i - 1].timeOffset;
			fwrite(&u32, sizeof(uint32_t), 1, output);
		}

		u8 = 0x66;
		fwrite(&u8, sizeof(uint8_t), 1, output);
		u32 = packetList[i].packetLength;
		fwrite(&u32, sizeof(uint32_t), 1, output);
		fwrite(packetList[i].packet.c_str(), packetList[i].packet.size(), 1, output);
	}

	u8 = 0x63;
	fwrite(&u8, sizeof(uint8_t), 1, output);
	u32 = packetList[packetList.size() - 1].timeOffset;
	fwrite(&u32, sizeof(uint32_t), 1, output);

	fclose(output);
}

void saveTtm(const std::string path, std::vector<Packet> packetList)
{
#ifdef DEBUG
	fprintf(pFile, "packetList: %d\n", packetList.size());
	fflush(pFile);
#endif

	FILE* output = fopen(path.c_str(), "wb");
	uint8_t u8 = 0;
	uint32_t u32 = 0;
	fwrite(&clientVersion, sizeof(uint16_t), 1, output);
	fwrite(&u8, sizeof(uint8_t), 1, output); // host length
	u32 = packetList[packetList.size() - 1].timeOffset;
	fwrite(&u32, sizeof(uint32_t), 1, output);

	for (int i = 0; i < packetList.size(); ++i) {
		if (i > 0) {
			u8 = 0;
			fwrite(&u8, sizeof(uint8_t), 1, output);
			u32 = packetList[i].timeOffset;
			fwrite(&u32, sizeof(uint32_t), 1, output);
		}

		fwrite(packetList[i].packet.c_str(), packetList[i].packet.size(), 1, output);
	}

	fclose(output);
}

void processDir(const char* directoryPath)
{
#ifdef DEBUG
	printf("processDir, directoryPath: %s\n", directoryPath);
#endif
	DIR* directory = opendir(directoryPath);

	if (directory == NULL) {
		perror("");
		return;
	}

	struct dirent* directoryEntry;

	while ((directoryEntry = readdir(directory)) != NULL) {
		if (strcmp(directoryEntry->d_name, ".") == 0 || strcmp(directoryEntry->d_name, "..") == 0) {
			continue;
		}

		std::string path = std::string(directoryPath) + directoryEntry->d_name;
		const char* extension = get_filename_ext(directoryEntry->d_name);
#ifdef DEBUG
		printf(
			"file: %s, type: %d, is_dir: %d, extension: %s, cmp: %d\n",
			path.c_str(),
			directoryEntry->d_type,
			directoryEntry->d_type == 0x4000,
			extension,
			strcmp(extension, "rec")
		);
#endif
		if (directoryEntry->d_type == 0x4000) {
			processDir((path + "/").c_str());
			continue;
		}

		if (strcmp(extension, "rec") == 0) {
			std::vector<Packet> packetList = loadRec(path);
			saveByn(path + ".byn", packetList);
			saveTtm(path + ".ttm", packetList);
		}
	}

	closedir(directory);
}

int main()
{
#ifdef DEBUG
	pFile = fopen("main1.log", "w");
#endif
	processDir("./");
}
