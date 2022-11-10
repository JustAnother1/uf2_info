#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>

static bool analyze_block(unsigned int num);
static void check_familyID(uint32_t id);
static void reportFamilyId(uint32_t id);
static void report_payload_size(uint32_t size);
static void report_memory_areas(uint32_t targetAddr, uint32_t size);
static void finish_reports(void);

struct UF2_Block {
    // 32 byte header
    uint32_t magicStart0;
    uint32_t magicStart1;
    uint32_t flags;
    uint32_t targetAddr;
    uint32_t payloadSize;
    uint32_t blockNo;
    uint32_t numBlocks;
    uint32_t fileSize; // or familyID;
    uint8_t data[476];
    uint32_t magicEnd;
} UF2_Block;

uint32_t familyID = 0;
uint32_t payload_size = 0;

uint32_t cur_mem_area_start = 0;
uint32_t cur_mem_area_end = 0;


static void report_memory_areas(uint32_t targetAddr, uint32_t size)
{
    if(0 == cur_mem_area_start)
    {
        // first block
        cur_mem_area_start = targetAddr;
        cur_mem_area_end = targetAddr + size;
    }
    else if(cur_mem_area_end == targetAddr)
    {
        cur_mem_area_end = cur_mem_area_end + size;
    }
    else
    {
        printf("Memory from 0x%08x until 0x%08x (size: %d bytes)\n",
            cur_mem_area_start, cur_mem_area_end, cur_mem_area_end - cur_mem_area_start);
        cur_mem_area_start = targetAddr;
        cur_mem_area_end = targetAddr + size;
    }
}

static void finish_reports(void)
{
    printf("Memory from 0x%08x until 0x%08x (size: %d bytes)\n",
        cur_mem_area_start, cur_mem_area_end, cur_mem_area_end - cur_mem_area_start);
}

static void report_payload_size(uint32_t size)
{
    if(0 == payload_size)
    {
        // first Packet
        printf("payload size is %d bytes\n", size);
        payload_size = size;
    }
    else if(payload_size != size)
    {
        printf("payload size changed from  %d bytes to %d bytes\n", payload_size, size);
    }
    // else no change -> OK
}

// family ID definition is here : https://github.com/microsoft/uf2/blob/master/utils/uf2families.json
static void reportFamilyId(uint32_t id)
{
    printf("Found Family id: ");
    switch(id)
    {
    case 0x16573617: printf("Microchip (Atmel) ATmega32\n");break;
    case 0x1851780a: printf("Microchip (Atmel) SAML21\n");break;
    case 0x1b57745f: printf("Nordic NRF52\n"); break;
    case 0x1c5f21b0: printf("ESP32\n"); break;
    case 0x1e1f432d: printf("ST STM32L1xx\n"); break;
    case 0x202e3a91: printf("ST STM32L0xx\n"); break;
    case 0x21460ff0: printf("ST STM32WLxx\n"); break;
    case 0x2abc77ec: printf("NXP LPC55xx\n"); break;
    case 0x300f5633: printf("ST STM32G0xx\n"); break;
    case 0x31d228c6: printf("GD32F350\n"); break;
    case 0x04240bdf: printf("ST STM32L5xx\n"); break;
    case 0x4c71240a: printf("ST STM32G4xx\n"); break;
    case 0x4fb2d5bd: printf("NXP i.MX RT10XX\n"); break;
    case 0x53b80f00: printf("ST STM32F7xx\n"); break;
    case 0x55114460: printf("Microchip (Atmel) SAMD51\n"); break;
    case 0x57755a57: printf("ST STM32F4xx\n"); break;
    case 0x5a18069b: printf("Cypress FX2\n"); break;
    case 0x5d1a0a2e: printf("ST STM32F2xx\n"); break;
    case 0x5ee21072: printf("ST STM32F103\n"); break;
    case 0x621e937a: printf("Nordic NRF52833\n"); break;
    case 0x647824b6: printf("ST STM32F0xx\n"); break;
    case 0x68ed2b88: printf("Microchip (Atmel) SAMD21\n"); break;
    case 0x6b846188: printf("ST STM32F3xx\n"); break;
    case 0x6d0922fa: printf("ST STM32F407\n"); break;
    case 0x6db66082: printf("ST STM32H7xx\n"); break;
    case 0x70d16653: printf("ST STM32WBxx\n"); break;
    case 0x7eab61ed: printf("ESP8266\n"); break;
    case 0x7f83e793: printf("NXP KL32L2x\n"); break;
    case 0x8fb060fe: printf("ST STM32F407VG\n"); break;
    case 0xada52840: printf("Nordic NRF52840\n"); break;
    case 0xbfdd4eee: printf("ESP32-S2\n"); break;
    case 0xc47e5767: printf("ESP32-S3\n"); break;
    case 0xd42ba06c: printf("ESP32-C3\n"); break;
    case 0x2b88d29c: printf("ESP32-C2\n"); break;
    case 0x332726f6: printf("ESP32-H2\n"); break;
    case 0xe48bff56: printf("Raspberry Pi RP2040\n"); break;
    case 0x00ff6919: printf("ST STM32L4xx\n"); break;
    case 0x9af03e33: printf("GigaDevice GD32VF103\n"); break;
    case 0x4f6ace52: printf("LISTENAI CSK300x/400x\n"); break;
    case 0x6e7348a8: printf("LISTENAI CSK60xx\n"); break;
    default: printf("unknown family id 0x%08x\n", id); break;
    }
}

static void check_familyID(uint32_t id)
{
    if(0 == familyID)
    {
        // first packet -> accept whatever family we found
        familyID = id;
        reportFamilyId(id);
    }
    else if(familyID != id)
    {
        printf("ERROR: family id changed !");
        reportFamilyId(id);
    }
    // else -> OK
}

static bool analyze_block(unsigned int num)
{
    unsigned int i;

    // magic numbers
    if(0x0A324655 != UF2_Block.magicStart0)
    {
        return false;
    }
    if(0x9E5D5157 != UF2_Block.magicStart1)
    {
        return false;
    }
    if(0x0AB16F30 != UF2_Block.magicEnd)
    {
        return false;
    }

    // Flags
    if(0 != (UF2_Block.flags & 0x00000001))
    {
        // not main flash
        // - this block should be skipped when writing the device flash;
        // it can be used to store "comments" in the file, typically embedded
        // source code or debug info that does not fit on the device flash
        printf("found -not main flash- flag in block %d\n", num);
    }
    if(0 != (UF2_Block.flags & 0x00001000))
    {
        // file container
        printf("found -not main flash- flag in block %d\n", num);
    }
    if(0 != (UF2_Block.flags & 0x00002000))
    {
        check_familyID(UF2_Block.fileSize);
    }
    else
    {
        // familyID present
        // UF2_Block.fileSize holds a value identifying the board family (usually corresponds to an MCU)
        printf("missing -familyID present- flag in block %d\n", num);
    }
    if(0 != (UF2_Block.flags & 0x00004000))
    {
        // MD5 checksum present
        printf("found -MD5 checksum present- flag in block %d\n", num);
    }
    if(0 != (UF2_Block.flags & 0x00008000))
    {
        // extension tags present
        printf("found -extension tags present- flag in block %d\n", num);
    }

    // payload size
    report_payload_size(UF2_Block.payloadSize);
    for(i = UF2_Block.payloadSize; i < 476; i++)
    {
        if(0 != UF2_Block.data[i])
        {
            printf("padding error! block %d, byte %d\n", num, i);
        }
    }

    report_memory_areas(UF2_Block.targetAddr, UF2_Block.payloadSize);
    // everything was OK
    return true;
}

int main(int argc, char *argv[])
{
    struct stat file_info;
    unsigned int file_size;
    unsigned int blocks;
    FILE* uf2_file;
    unsigned int i;

    if(512 != sizeof(UF2_Block))
    {
        fprintf(stderr, "compile issue - padding !\n");
        return -1;
    }

    if(2 > argc)
    {
        fprintf(stderr, "usage: %s file.uf2\n", argv[0]);
        return 1;
    }

    if(stat(argv[1], &file_info) != 0)
    {
        fprintf(stderr, "can not get file information for %s\n", argv[1]);
        return 2;
    }
    file_size = file_info.st_size;
    printf("file size %d bytes\n", file_size);
    blocks = file_size / 512;
    if(blocks * 512 != file_size)
    {
        fprintf(stderr, "invalid file size  of %d bytes\n", file_size);
        return 3;
    }
    printf("file has %d blocks\n", blocks);

    uf2_file = fopen(argv[1], "rb");
    if(NULL == uf2_file)
    {
        fprintf(stderr, "can not read the file  %s\n", argv[1]);
        return 4;
    }

    for(i = 0; i < blocks; i++)
    {
        // read one block
        size_t num = fread(&UF2_Block, 512, 1, uf2_file);
        // analyze the block
        if(UF2_Block.numBlocks != blocks)
        {
            fprintf(stderr, "block %d reports wrong number of blocks (should be %d, but is %d)\n", i, blocks, UF2_Block.numBlocks);
            return 5;
        }
        if(UF2_Block.blockNo != i)
        {
            fprintf(stderr, "block number is %d but should %d\n", UF2_Block.blockNo, i);
            return 6;
        }
        if(false == analyze_block(i))
        {
            fprintf(stderr, "block %d has invalid data\n", i);
            return 7;
        }
    }

    finish_reports();

    fclose(uf2_file);
    printf("file is valid\n");
    return 0;
}
