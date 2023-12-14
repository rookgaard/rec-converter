#include <iostream>
#include <vector>
#include "file.h"
#include "aes256.h"
#include "dirent.h"
#include "zlib.h"

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

		for (int i = 0; i < packets; i++) {
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
				fseek(input, 4, SEEK_CUR); // unused
			}
			else {
				std::string packet;
				packet.resize(packetLength);
				fread(&packet[0], 1, packetLength, input);
				fseek(input, 4, SEEK_CUR); // unused
				BYTE Key = packetLength + timeOffset + 2;

				for (WORD i = 0; i < packetLength; i++) {
					CHAR Minus = Key + 33 * i;

					if (Minus < 0) {
						while (-Minus % Mod) Minus++;
					}
					else {
						while (Minus % Mod) Minus++;
					}

					packet[i] -= Minus;
				}

				if (version > 4) {
					const char* charPacket = packet.c_str();
					LPBYTE bPacket = (LPBYTE)charPacket;
					Aes256::decrypt(LPBYTE("Thy key is mine © 2006 GB Monaco"), bPacket, packetLength);
					// after decrypting, real packet size is on first 2 bytes of packet
					packetLength = bPacket[0] + bPacket[1] * 256;
					packet = packet.substr(0, packetLength + 2);
				}

				packetList.push_back(Packet(timeOffset, packet));
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
				packetList.push_back(Packet(timeOffset, packet));
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

std::vector<Packet> loadCam(const std::string path)
{
	std::vector<Packet> packetList;
	FILE* input = fopen(path.c_str(), "rb");
	uint32_t headerLength;
	fread(&headerLength, sizeof(uint32_t), 1, input);
#ifdef DEBUG
	fprintf(pFile, "headerLength: %d\n", headerLength);
	fflush(pFile);
#endif
	fseek(input, headerLength, SEEK_CUR); // unused
	uint32_t timestamp;
	fread(&timestamp, sizeof(uint32_t), 1, input);
#ifdef DEBUG
	fprintf(pFile, "timestamp: %d\n", timestamp);
	fflush(pFile);
#endif
	fseek(input, -4, SEEK_CUR);

	while (!feof(input)) {
		uint32_t timeOffset;
		fread(&timeOffset, sizeof(uint32_t), 1, input);
#ifdef DEBUG
		fprintf(pFile, "timeOffset: %d\n", timeOffset);
		fflush(pFile);
#endif
		fseek(input, 4, SEEK_CUR); // 00 00 00 00

		uint16_t packetLength;
		fread(&packetLength, sizeof(uint16_t), 1, input);
#ifdef DEBUG
		fprintf(pFile, "packetLength: %d\n", packetLength);
		fflush(pFile);
#endif

		std::string packet;
		packet.resize(packetLength + 2);
		fseek(input, -2, SEEK_CUR);
		fread(&packet[0], 1, packetLength + 2, input);

		packetList.push_back(Packet(timeOffset - timestamp, packet));
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
	FILE* output = fopen(path.c_str(), "wb");
	uint8_t u8 = 0x64;
	uint16_t u16 = 0;
	uint32_t u32 = 0;
	fwrite(&u8, sizeof(uint8_t), 1, output);
	fwrite(&clientVersion, sizeof(uint16_t), 1, output);

	for (size_t i = 0; i < packetList.size(); ++i) {
		u8 = 0x65;
		fwrite(&u8, sizeof(uint8_t), 1, output);

		if (i == 0) {
			u16 = 0;
			fwrite(&u16, sizeof(uint16_t), 1, output);
		}
		else {
			u16 = packetList[i].timeOffset - packetList[i - 1].timeOffset;
			fwrite(&u16, sizeof(uint16_t), 1, output);
		}

		u8 = 0x66;
		fwrite(&u8, sizeof(uint8_t), 1, output);
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
	FILE* output = fopen(path.c_str(), "wb");
	uint8_t u8 = 0;
	uint16_t u16 = 0;
	uint32_t u32 = 0;
	fwrite(&clientVersion, sizeof(uint16_t), 1, output);
	fwrite(&u8, sizeof(uint8_t), 1, output); // host length
	u32 = packetList[packetList.size() - 1].timeOffset;
	fwrite(&u32, sizeof(uint32_t), 1, output);

	for (size_t i = 0; i < packetList.size(); ++i) {
		if (i > 0) {
			u8 = 0;
			fwrite(&u8, sizeof(uint8_t), 1, output);
			u16 = packetList[i].timeOffset - packetList[i - 1].timeOffset;
			fwrite(&u16, sizeof(uint16_t), 1, output);
		}

		fwrite(packetList[i].packet.c_str(), packetList[i].packet.size(), 1, output);
	}

	fclose(output);
}

void saveRecord(const std::string path, std::vector<Packet> packetList)
{
	FILE* output = fopen(path.c_str(), "wb");

	for (size_t i = 0; i < packetList.size(); ++i) {
		fprintf(output, "< %d %s\n", packetList[i].timeOffset, string_to_hex(packetList[i].packet).c_str());
	}

	fclose(output);
}

void saveTmv(const std::string path, std::vector<Packet> packetList)
{
	gzFile output = gzopen(path.c_str(), "wb");
	uint8_t u8 = 0;
	uint16_t u16 = 2;
	uint32_t u32 = 0;
	gzwrite(output, &u16, sizeof(uint16_t)); // tmv version
	gzwrite(output, &clientVersion, sizeof(uint16_t));
	u32 = packetList[packetList.size() - 1].timeOffset;
	gzwrite(output, &u32, sizeof(uint32_t));

	for (size_t i = 0; i < packetList.size(); ++i) {
		u8 = 0;
		gzwrite(output, &u8, sizeof(uint8_t));
		u16 = i == 0 ? 0 : packetList[i].timeOffset - packetList[i - 1].timeOffset;
		gzwrite(output, &u16, sizeof(uint16_t));
		gzwrite(output, packetList[i].packet.c_str(), packetList[i].packet.size());
	}

	gzclose(output);
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

		std::vector<Packet> packetList;

		if (strcmp(extension, "rec") == 0) {
			printf("path: %s\n", path.c_str());
			packetList = loadRec(path);
		}
		else if (strcmp(extension, "cam") == 0) {
			printf("path: %s\n", path.c_str());
			packetList = loadCam(path);
		}

		if (packetList.size()) {
			saveByn(path + ".byn", packetList);
			saveTtm(path + ".ttm", packetList);
			saveRecord(path + ".record", packetList);
			saveTmv(path + ".tmv", packetList);
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
