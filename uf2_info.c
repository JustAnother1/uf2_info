/*
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, see <http://www.gnu.org/licenses/>
 *
 */

#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <string.h>

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
    case 0x00ff6919: printf("ST STM32L4xx (0x00ff6919)\n");break;
    case 0x04240bdf: printf("ST STM32L5xx (0x04240bdf)\n");break;
    case 0x06d1097b: printf("ST STM32F411xC (0x06d1097b)\n");break;
    case 0x11de784a: printf("M0SENSE BL702 (0x11de784a)\n");break;
    case 0x16573617: printf("Microchip (Atmel) ATmega32 (0x16573617)\n");break;
    case 0x1851780a: printf("Microchip (Atmel) SAML21 (0x1851780a)\n");break;
    case 0x1b57745f: printf("Nordic NRF52 (0x1b57745f)\n");break;
    case 0x1c5f21b0: printf("ESP32 (0x1c5f21b0)\n");break;
    case 0x1e1f432d: printf("ST STM32L1xx (0x1e1f432d)\n");break;
    case 0x202e3a91: printf("ST STM32L0xx (0x202e3a91)\n");break;
    case 0x21460ff0: printf("ST STM32WLxx (0x21460ff0)\n");break;
    case 0x22e0d6fc: printf("Realtek AmebaZ RTL8710B (0x22e0d6fc)\n");break;
    case 0x2abc77ec: printf("NXP LPC55xx (0x2abc77ec)\n");break;
    case 0x2b88d29c: printf("ESP32-C2 (0x2b88d29c)\n");break;
    case 0x2dc309c5: printf("ST STM32F411xE (0x2dc309c5)\n");break;
    case 0x300f5633: printf("ST STM32G0xx (0x300f5633)\n");break;
    case 0x31d228c6: printf("GD32F350 (0x31d228c6)\n");break;
    case 0x332726f6: printf("ESP32-H2 (0x332726f6)\n");break;
    case 0x3379CFE2: printf("Realtek AmebaD RTL8720D (0x3379CFE2)\n");break;
    case 0x3d308e94: printf("ESP32-P4 (0x3d308e94)\n");break;
    case 0x4b684d71: printf("Sipeed MaixPlay-U4(BL618) (0x4b684d71)\n");break;
    case 0x4c71240a: printf("ST STM32G4xx (0x4c71240a)\n");break;
    case 0x4f6ace52: printf("LISTENAI CSK300x/400x (0x4f6ace52)\n");break;
    case 0x4fb2d5bd: printf("NXP i.MX RT10XX (0x4fb2d5bd)\n");break;
    case 0x51e903a8: printf("Xradiotech 809 (0x51e903a8)\n");break;
    case 0x53b80f00: printf("ST STM32F7xx (0x53b80f00)\n");break;
    case 0x540ddf62: printf("ESP32-C6 (0x540ddf62)\n");break;
    case 0x55114460: printf("Microchip (Atmel) SAMD51 (0x55114460)\n");break;
    case 0x57755a57: printf("ST STM32F4xx (0x57755a57)\n");break;
    case 0x5a18069b: printf("Cypress FX2 (0x5a18069b)\n");break;
    case 0x5d1a0a2e: printf("ST STM32F2xx (0x5d1a0a2e)\n");break;
    case 0x5ee21072: printf("ST STM32F103 (0x5ee21072)\n");break;
    case 0x621e937a: printf("Nordic NRF52833 (0x621e937a)\n");break;
    case 0x647824b6: printf("ST STM32F0xx (0x647824b6)\n");break;
    case 0x675a40b0: printf("Beken 7231U/7231T (0x675a40b0)\n");break;
    case 0x68ed2b88: printf("Microchip (Atmel) SAMD21 (0x68ed2b88)\n");break;
    case 0x699b62ec: printf("WCH CH32V2xx and CH32V3xx (0x699b62ec)\n");break;
    case 0x6a82cc42: printf("Beken 7251/7252 (0x6a82cc42)\n");break;
    case 0x6b846188: printf("ST STM32F3xx (0x6b846188)\n");break;
    case 0x6d0922fa: printf("ST STM32F407 (0x6d0922fa)\n");break;
    case 0x6db66082: printf("ST STM32H7xx (0x6db66082)\n");break;
    case 0x6e7348a8: printf("LISTENAI CSK60xx (0x6e7348a8)\n");break;
    case 0x6f752678: printf("Nordic NRF52832xxAB (0x6f752678)\n");break;
    case 0x70d16653: printf("ST STM32WBxx (0x70d16653)\n");break;
    case 0x72721d4e: printf("Nordic NRF52832xxAA (0x72721d4e)\n");break;
    case 0x77d850c4: printf("ESP32-C61 (0x77d850c4)\n");break;
    case 0x7b3ef230: printf("Beken 7231N (0x7b3ef230)\n");break;
    case 0x7be8976d: printf("Renesas RA4M1 (0x7be8976d)\n");break;
    case 0x7eab61ed: printf("ESP8266 (0x7eab61ed)\n");break;
    case 0x7f83e793: printf("NXP KL32L2x (0x7f83e793)\n");break;
    case 0x8fb060fe: printf("ST STM32F407VG (0x8fb060fe)\n");break;
    case 0x9517422f: printf("Renesas RZ/A1LU (R7S7210xx) (0x9517422f)\n");break;
    case 0x9af03e33: printf("GigaDevice GD32VF103 (0x9af03e33)\n");break;
    case 0x9fffd543: printf("Realtek Ameba1 RTL8710A (0x9fffd543)\n");break;
    case 0xa0c97b8e: printf("ArteryTek AT32F415 (0xa0c97b8e)\n");break;
    case 0xada52840: printf("Nordic NRF52840 (0xada52840)\n");break;
    case 0xbfdd4eee: printf("ESP32-S2 (0xbfdd4eee)\n");break;
    case 0xc47e5767: printf("ESP32-S3 (0xc47e5767)\n");break;
    case 0xd42ba06c: printf("ESP32-C3 (0xd42ba06c)\n");break;
    case 0xde1270b7: printf("Boufallo 602 (0xde1270b7)\n");break;
    case 0xe08f7564: printf("Realtek AmebaZ2 RTL8720C (0xe08f7564)\n");break;
    case 0xe48bff56: printf("Raspberry Pi RP2040 (0xe48bff56)\n");break;
    case 0xe48bff57: printf("Raspberry Pi Microcontrollers: Absolute (unpartitioned) download (0xe48bff57)\n");break;
    case 0xe48bff58: printf("Raspberry Pi Microcontrollers: Data partition download (0xe48bff58)\n");break;
    case 0xe48bff59: printf("Raspberry Pi RP2350, Secure Arm image (0xe48bff59)\n");break;
    case 0xe48bff5a: printf("Raspberry Pi RP2350, RISC-V image (0xe48bff5a)\n");break;
    case 0xe48bff5b: printf("Raspberry Pi RP2350, Non-secure Arm image (0xe48bff5b)\n");break;
    case 0xf71c0343: printf("ESP32-C5 (0xf71c0343)\n");break;
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

void dump_block(unsigned int num)
{
    unsigned int i;
    uint32_t block_mem_start = cur_mem_area_end -UF2_Block.payloadSize;
    printf("block %d data (0x%08x - 0x%08x):", num, block_mem_start, cur_mem_area_end);
    for(i = 0; i < UF2_Block.payloadSize; i++)
    {
        if(0 == i%16)
        {
            printf("\n0x%08x :", block_mem_start + i);
        }
        printf(" %02x", UF2_Block.data[i]);
    }
    printf("\n\n");
}

void create_bin_from_block(unsigned int num)
{
    FILE* binf;
    char filename[30] = {0};
    sprintf(filename, "%d.bin", num);
    binf = fopen(filename, "w");
    fwrite(UF2_Block.data, UF2_Block.payloadSize, 1, binf);
    fclose(binf);
}

int main(int argc, char *argv[])
{
    struct stat file_info;
    unsigned int file_size;
    unsigned int blocks;
    FILE* uf2_file;
    unsigned int i;
    char * fileName;
    bool do_dump = false;
    bool make_bins = false;

    if(512 != sizeof(UF2_Block))
    {
        fprintf(stderr, "compile issue - padding !\n");
        return -1;
    }

    if(2 > argc)
    {
        fprintf(stderr, "usage: %s [-d] [-b] file.uf2\n", argv[0]);
        return 1;
    }

    if(0 == strcmp("-d", argv[1]))
    {
        do_dump = true;
        fileName = argv[2];
    }
    else if(0 == strcmp("-b", argv[1]))
    {
        make_bins = true;
        fileName = argv[2];
    }
    else
    {
        fileName = argv[1];
    }

    if(stat(fileName, &file_info) != 0)
    {
        fprintf(stderr, "can not get file information for %s\n", fileName);
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

    uf2_file = fopen(fileName, "rb");
    if(NULL == uf2_file)
    {
        fprintf(stderr, "can not read the file  %s\n", fileName);
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
        if(true == do_dump)
        {
            dump_block(i);
        }
        if(true == make_bins)
        {
            create_bin_from_block(i);
        }
    }

    finish_reports();

    fclose(uf2_file);
    printf("file is valid\n");
    return 0;
}
