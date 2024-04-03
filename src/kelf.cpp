/*
 * Copyright (c) 2019 xfwcfw
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
#include <openssl/des.h>
#include <string.h>
#include <errno.h>

#include "kelf.h"
#include "common.h"

uint8_t MG_IV_NULL[8] = {0};

int TdesCbcCfb64Encrypt(void *Result, const void *Data, size_t Length, const void *Keys, int KeyCount, const void *IV)
{
    DES_key_schedule sc1;
    DES_key_schedule sc2;
    DES_key_schedule sc3;

    DES_set_key((const_DES_cblock *)Keys, &sc1);
    if (KeyCount >= 2)
        DES_set_key((const_DES_cblock *)((uint8_t *)Keys + 8), &sc2);
    if (KeyCount >= 3)
        DES_set_key((const_DES_cblock *)((uint8_t *)Keys + 16), &sc3);

    DES_cblock iv;
    memcpy(&iv, IV, 8);

    if (KeyCount == 1)
        DES_cbc_encrypt((uint8_t *)Data, (uint8_t *)Result, Length, &sc1, &iv, DES_ENCRYPT);
    if (KeyCount == 2)
        DES_ede2_cbc_encrypt((uint8_t *)Data, (uint8_t *)Result, Length, &sc1, &sc2, &iv, DES_ENCRYPT);
    if (KeyCount == 3)
        DES_ede3_cbc_encrypt((uint8_t *)Data, (uint8_t *)Result, Length, &sc1, &sc2, &sc3, &iv, DES_ENCRYPT);
    else
        return KELF_ERROR_INVALID_DES_KEY_COUNT;

    return 0;
}

int TdesCbcCfb64Decrypt(void *Result, const void *Data, size_t Length, const void *Keys, int KeyCount, const void *IV)
{
    DES_key_schedule sc1;
    DES_key_schedule sc2;
    DES_key_schedule sc3;

    DES_set_key((const_DES_cblock *)Keys, &sc1);
    if (KeyCount >= 2)
        DES_set_key((const_DES_cblock *)((uint8_t *)Keys + 8), &sc2);
    if (KeyCount >= 3)
        DES_set_key((const_DES_cblock *)((uint8_t *)Keys + 16), &sc3);

    DES_cblock iv;
    memcpy(&iv, IV, 8);

    if (KeyCount == 1)
        DES_cbc_encrypt((uint8_t *)Data, (uint8_t *)Result, Length, &sc1, &iv, DES_DECRYPT);
    if (KeyCount == 2)
        DES_ede2_cbc_encrypt((uint8_t *)Data, (uint8_t *)Result, Length, &sc1, &sc2, &iv, DES_DECRYPT);
    if (KeyCount == 3)
        DES_ede3_cbc_encrypt((uint8_t *)Data, (uint8_t *)Result, Length, &sc1, &sc2, &sc3, &iv, DES_DECRYPT);
    else
        return KELF_ERROR_INVALID_DES_KEY_COUNT;

    return 0;
}

void xor_bit(const void *a, const void *b, void *Result, size_t Length)
{
    size_t i;
    for (i = 0; i < Length; i++) {
        ((uint8_t *)Result)[i] = ((uint8_t *)a)[i] ^ ((uint8_t *)b)[i];
    }
}

int Kelf::LoadKelf(const std::string &filename)
{
    FILE *f = fopen(filename.c_str(), "rb");
    if (f == NULL) {
        fprintf(stderr, "Couldn't open %s: %s\n", filename.c_str(), strerror(errno));
        return KELF_ERROR_UNSUPPORTED_FILE;
    }

    KELFHeader header;
    fread(&header, sizeof(header), 1, f);

    if (header.Flags & 1 || header.Flags & 0xf0000 || header.BitCount != 0) {
        // TODO: check more unknown bit flags
        printf(REDBOLD"This file is not supported yet and looked after.\n");
        printf("Please upload it and post it under that issue:\n");
        printf(YELBOLD"https://github.com/xfwcfw/kelftool/issues/1\n"DEFCOL);
        // fclose(f);
        // return KELF_ERROR_UNSUPPORTED_FILE;
    }
    printf("header.UserDefined     ="YELLOW);
    for (size_t i = 0; i < sizeof(header.UserDefined); ++i)
        printf(" %02X", header.UserDefined[i]);
    if (!memcmp(header.UserDefined, USER_HEADER_FMCB, 16))
        printf(GREEN" (FMCB)\n"DEFCOL);
    if (!memcmp(header.UserDefined, USER_HEADER_DNASLOAD, 16))
        printf(GREEN" (DNASLOAD)\n"DEFCOL);
    else if (!memcmp(header.UserDefined, USER_HEADER_FHDB, 16))
        printf(GREEN" (FHDB)\n"DEFCOL);
    else if (!memcmp(header.UserDefined, USER_HEADER_MBR, 16))
        printf(GREEN" (MBR)\n"DEFCOL);
    else
        printf(DEFCOL" (UNKNOWN)\n");

    printf("header.ContentSize     = "YELLOW"%#X\n"DEFCOL, header.ContentSize);
    printf("header.HeaderSize      = "YELLOW"%#X\n"DEFCOL, header.HeaderSize);
    printf("header.SystemType      = "YELLOW"%#X ", header.SystemType);
    switch (header.SystemType) {
        case 0:
            printf(GREEN"(SYSTEM_TYPE_PS2)"DEFCOL"\n");
            break;
        case 1:
            printf(GREEN"(SYSTEM_TYPE_PSX)"DEFCOL"\n");
            break;
        default:
            printf(DEFCOL"(UNKNOWN)\n");
            printf(REDBOLD"    This value is unknown.\n");
            printf("    Please upload file and post under that issue:\n");
            printf(YELBOLD"    https://github.com/xfwcfw/kelftool/issues/1\n"DEFCOL);
            break;
    }

    printf("header.ApplicationType = "YELLOW"%#X ", header.ApplicationType);
    switch (header.ApplicationType) {
        case KELFTYPE_DISC_WOOBLE:
            printf(GREEN"(disc wobble \?)\n");
            break;
        case KELFTYPE_XOSDMAIN:
            printf(GREEN"(xosdmain)\n");
            break;
        case KELFTYPE_DVDPLAYER_KIRX:
            printf(GREEN"(dvdplayer kirx)\n");
            break;
        case KELFTYPE_DVDPLAYER_KELF:
            printf(GREEN"(dvdplayer kelf)\n");
            break;
        case KELFTYPE_EARLY_MBR:
            printf(GREEN"(early mbr \?)\n");
            break;
        default:
            printf(DEFCOL"(UNKNOWN)\n");
            printf(REDBOLD"    This value is unknown.\n");
            printf("    Please upload file and post under that issue:\n");
            printf(YELBOLD"    https://github.com/xfwcfw/kelftool/issues/1\n"DEFCOL);
            break;
    }
    printf(DEFCOL"header.Flags           = "YELLOW"%#X "DEFCOL, header.Flags);
    if (header.Flags == HDR_PREDEF_KELF)
        printf(" - "GREENBOLD"kelf"DEFCOL":");
    else if (header.Flags == HDR_PREDEF_KIRX)
        printf(" - "GREENBOLD"kirx"DEFCOL":");
    else
        printf(" - "RED"unknown"DEFCOL":");
    if (header.Flags & HDR_FLAG0_BLACKLIST)
        printf(GREEN"HDR_FLAG0_BLACKLIST"DEFCOL"|");
    if (header.Flags & HDR_FLAG1_WHITELIST)
        printf(GREEN"HDR_FLAG1_WHITELIST"DEFCOL"|");
    if (header.Flags & HDR_FLAG2)
        printf(GREEN"HDR_FLAG2"DEFCOL"|");
    if (header.Flags & HDR_FLAG3)
        printf(GREEN"HDR_FLAG3"DEFCOL"|");
    if (header.Flags & HDR_FLAG4_1DES)
        printf(GREEN"HDR_FLAG4_1DES"DEFCOL"|");
    if (header.Flags & HDR_FLAG4_3DES)
        printf(GREEN"HDR_FLAG4_3DES"DEFCOL"|");
    if (header.Flags & HDR_FLAG6)
        printf(GREEN"HDR_FLAG6"DEFCOL"|");
    if (header.Flags & HDR_FLAG7)
        printf(GREEN"HDR_FLAG7"DEFCOL"|");
    if (header.Flags & HDR_FLAG8)
        printf(GREEN"HDR_FLAG8"DEFCOL"|");
    if (header.Flags & HDR_FLAG9)
        printf(GREEN"HDR_FLAG9"DEFCOL"|");
    if (header.Flags & HDR_FLAG10)
        printf(GREEN"HDR_FLAG10"DEFCOL"|");
    if (header.Flags & HDR_FLAG11)
        printf(GREEN"HDR_FLAG11"DEFCOL"|");
    if (header.Flags & HDR_FLAG12)
        printf(GREEN"HDR_FLAG12"DEFCOL"|");
    if (header.Flags & HDR_FLAG13)
        printf(GREEN"HDR_FLAG13"DEFCOL"|");
    if (header.Flags & HDR_FLAG14)
        printf(GREEN"HDR_FLAG14"DEFCOL"|");
    if (header.Flags & HDR_FLAG15)
        printf(GREEN"HDR_FLAG15"DEFCOL"|");
    printf("\n");

    printf("header.BitCount        = "YELLOW"%#X \n"DEFCOL, header.BitCount);
    printf("header.MGZones         = "YELLOW"%#X "DEFCOL" |", header.MGZones);
    if (header.MGZones == 0)
        printf(REDBOLD"All regions blocked (useless)|"DEFCOL);
    else if (header.MGZones == REGION_ALL_ALLOWED)
        printf(GREENBOLD"All regions allowed"DEFCOL"|");
    else {
        if (header.MGZones & REGION_JP)
            printf(GREEN"Japan"DEFCOL"|");
        if (header.MGZones & REGION_NA)
            printf(GREEN"North America"DEFCOL"|");
        if (header.MGZones & REGION_EU)
            printf(GREEN"Europe"DEFCOL"|");
        if (header.MGZones & REGION_AU)
            printf(GREEN"Australia"DEFCOL"|");
        if (header.MGZones & REGION_ASIA)
            printf(GREEN"Asia"DEFCOL"|");
        if (header.MGZones & REGION_RU)
            printf(GREEN"Russia"DEFCOL"|");
        if (header.MGZones & REGION_CH)
            printf(GREEN"China"DEFCOL"|");
        if (header.MGZones & REGION_MX)
            printf(GREEN"Mexico"DEFCOL"|");
    }
    printf("\n");

    printf("header.gap             ="YELLOW);
    for (unsigned int i = 0; i < 3; ++i)
        printf(" %02X", (unsigned char)header.gap[i]);
    printf(DEFCOL"\n");

    std::string HeaderSignature;
    HeaderSignature.resize(8);
    fread(HeaderSignature.data(), 1, HeaderSignature.size(), f);
    printf("HeaderSignature        ="YELLOW);
    for (size_t i = 0; i < 8; ++i)
        printf(" %02X", (unsigned char)HeaderSignature[i]);
    printf(DEFCOL);

    if (HeaderSignature != GetHeaderSignature(header)) {
        fclose(f);
        return KELF_ERROR_INVALID_HEADER_SIGNATURE;
    }

    std::string KEK = DeriveKeyEncryptionKey(header);

    Kbit.resize(16);
    fread(Kbit.data(), 1, Kbit.size(), f);

    Kc.resize(16);
    fread(Kc.data(), 1, Kc.size(), f);
    DecryptKeys(KEK);

    printf("\nKbit                   ="YELLOW);
    for (size_t i = 0; i < 16; ++i)
        printf(" %02X", (unsigned char)Kbit[i]);

    printf(DEFCOL"\nKc                     ="YELLOW);
    for (size_t i = 0; i < 16; ++i)
        printf(" %02X", (unsigned char)Kc[i]);
    printf(DEFCOL);
    
    if (ks.GetOverrideKbit().size() && ks.GetOverrideKc().size()) {
        printf("\n-- Kbit and Kc overriden by Keystore!");
        memcpy(Kbit.data(), ks.GetOverrideKbit().data(), 16);
        memcpy(Kc.data(), ks.GetOverrideKc().data(), 16);
    }

    int BitTableSize = header.HeaderSize - ftell(f) - 8 - 8;
    printf("\nBitTableSize           = "YELLOW"%#X\n"DEFCOL, BitTableSize);
    if (BitTableSize > sizeof(BitTable)) {
        fclose(f);
        return KELF_ERROR_INVALID_BIT_TABLE_SIZE;
    }

    fread(&bitTable, 1, BitTableSize, f);

    TdesCbcCfb64Decrypt((uint8_t *)&bitTable, (uint8_t *)&bitTable, BitTableSize, (uint8_t *)Kbit.data(), 2, ks.GetContentTableIV().data());
    printf("bitTable.HeaderSize    = "YELLOW"%#X\n"DEFCOL, bitTable.HeaderSize);
    printf("bitTable.BlockCount    = "YELLOW"%d\n"DEFCOL, bitTable.BlockCount);
    printf("bitTable.gap           ="YELLOW);
    for (unsigned int i = 0; i < 3; ++i)
        printf(" %02X", (unsigned char)bitTable.gap[i]);
    printf(DEFCOL"\n                         Size        Signature           Flags\n");
    for (unsigned int i = 0; i < bitTable.BlockCount; ++i) {
        printf(DEFCOL"    bitTable.Blocks[%d] = "YELLOW"%08X    ", (int)i, bitTable.Blocks[i].Size);
        for (size_t j = 0; j < 8; ++j)
            printf("%02X", (unsigned char)bitTable.Blocks[i].Signature[j]);
        printf("    %08X"DEFCOL, bitTable.Blocks[i].Flags);
        switch (bitTable.Blocks[i].Flags) {
            case 0:
                printf(" ("GREEN"not encrypted, not signed"DEFCOL")\n");
                break;
            case 1:
                printf(" ("GREEN"encrypted only"DEFCOL")\n");
                break;
            case 2:
                printf(" ("GREEN"signed only"DEFCOL")\n");
                break;
            case 3:
                printf(" ("GREEN"encrypted and signed"DEFCOL")\n");
                break;
            default:
                printf(" (unknown set of flags)\n");
                printf(REDBOLD"This value is unknown.\n");
                printf("Please upload file and post under that issue:\n");
                printf(YELBOLD"https://github.com/xfwcfw/kelftool/issues/1\n"DEFCOL);
                break;
        }
    }


    std::string BitTableSignature;
    BitTableSignature.resize(8);
    fread(BitTableSignature.data(), 1, BitTableSignature.size(), f);
    printf("BitTableSignature      ="YELLOW);
    for (size_t i = 0; i < 8; ++i)
        printf(" %02X", (unsigned char)BitTableSignature[i]);
    printf(DEFCOL"\n");

    if (BitTableSignature != GetBitTableSignature()) {
        fclose(f);
        return KELF_ERROR_INVALID_BIT_TABLE_SIGNATURE;
    }

    std::string RootSignature;
    RootSignature.resize(8);
    fread(RootSignature.data(), 1, RootSignature.size(), f);
    if (RootSignature != GetRootSignature(HeaderSignature, BitTableSignature)) {
        printf(YELBOLD"\nWARNING: RootSignature does not match         =");
        for (size_t i = 0; i < 8; ++i)
            printf(" %02X", (unsigned char)RootSignature[i]);
        printf(DEFCOL"\n");

        // fclose(f);
        // return KELF_ERROR_INVALID_ROOT_SIGNATURE;
    }
    for (int i = 0; i < bitTable.BlockCount; i++) {
        std::string Block;
        Block.resize(bitTable.Blocks[i].Size);
        fread(Block.data(), 1, Block.size(), f);
        Content += Block;
    }

    DecryptContent(header.Flags >> 4 & 3);

    if (VerifyContentSignature() != 0) {
        printf(YELBOLD"WARNING: VerifyContentSignature does not match\n"DEFCOL);
        fclose(f);
        return KELF_ERROR_INVALID_CONTENT_SIGNATURE;
    }

    fclose(f);

    return 0;
}
extern uint8_t GSystemtype;
extern uint8_t GMGZones;
extern uint16_t GFlags;
extern uint8_t GApplicationType;

int Kelf::SaveKelf(const std::string &filename, int headerid)
{
    FILE *f = fopen(filename.c_str(), "wb");
    if (f == NULL) {
        fprintf(stderr, "Couldn't open %s: %s\n", filename.c_str(), strerror(errno));
        return KELF_ERROR_UNSUPPORTED_FILE;
    }
    KELFHeader header;

    static uint8_t *USER_HEADER;

    switch (headerid) {
        case HEADER::FMCB:
            USER_HEADER = USER_HEADER_FMCB;
            break;

 /* thanks to krHACKen. dnasload headers allows encrypting PS2 KELF and booting them on PSX-DESR without touching system type field.
    because this header is whitelisted on PSX */
        case HEADER::DNASLOAD:
        USER_HEADER = USER_HEADER_DNASLOAD;
            break;

        case HEADER::FHDB:
            USER_HEADER = USER_HEADER_FHDB;
            break;

        case HEADER::MBR:
            USER_HEADER = USER_HEADER_MBR;
            break;

        default:
            printf(YELLOW"WARNING: unknown header ID (%d) defaulting to FHDB ID\n"DEFCOL, headerid);
            USER_HEADER = USER_HEADER_FHDB;
            break;
    }

    memcpy(header.UserDefined, USER_HEADER, 16);
    header.ContentSize     = Content.size();      // sometimes zero
    header.HeaderSize      = bitTable.HeaderSize; // header + header signature + kbit + kc + bittable + bittable signature + root signature
    header.SystemType      = GSystemtype;     // same for COH (arcade)
    header.ApplicationType = GApplicationType;                   // 1 = xosdmain, 5 = dvdplayer kirx 7 = dvdplayer kelf 0xB - ?? 0x00 - ??
    // TODO: implement and check 3DES/1DES difference based on header.Flags. In both - encryption and decryption.
    header.Flags    = GFlags; // ?? 00000010 00101100 binary, 0x021C for kirx
    header.MGZones  = GMGZones;   // region bit, 1 - allowed
    header.BitCount = 0;
    // ?? balika, wisi: strange value, represents number of blacklisted iLinkID, ConsoleID
    // iLinkID (8 bytes), consoleID (8 bytes) placed between header.MGZones and HeaderSignature
    // it is part of header, so HeaderSignature and header.HeaderSize should be recalculated

    std::fill(header.gap, header.gap + 3, 0);

    std::string HeaderSignature   = GetHeaderSignature(header);
    std::string BitTableSignature = GetBitTableSignature();
    std::string RootSignature     = GetRootSignature(HeaderSignature, BitTableSignature);

    int BitTableSize = (bitTable.BlockCount * 2 + 1) * 8;
    TdesCbcCfb64Encrypt((uint8_t *)&bitTable, (uint8_t *)&bitTable, BitTableSize, (uint8_t *)Kbit.data(), 2, ks.GetContentTableIV().data());

    std::string KEK = DeriveKeyEncryptionKey(header);
    EncryptKeys(KEK);

    fwrite(&header, sizeof(header), 1, f);
    fwrite(HeaderSignature.data(), 1, HeaderSignature.size(), f);
    fwrite(Kbit.data(), 1, Kbit.size(), f);
    fwrite(Kc.data(), 1, Kc.size(), f);
    fwrite(&bitTable, 1, BitTableSize, f);
    fwrite(BitTableSignature.data(), 1, BitTableSignature.size(), f);
    fwrite(RootSignature.data(), 1, RootSignature.size(), f);

    fwrite(Content.data(), 1, Content.size(), f);
    fclose(f);

    return 0;
}

int Kelf::LoadContent(const std::string &filename, int headerid)
{
    FILE *f = fopen(filename.c_str(), "rb");
    if (f == NULL) {
        fprintf(stderr, "Couldn't open %s: %s\n", filename.c_str(), strerror(errno));
        return KELF_ERROR_UNSUPPORTED_FILE;
    }
    fseek(f, 0, SEEK_END);
    Content.resize(ftell(f));
    fseek(f, 0, SEEK_SET);
    fread(Content.data(), 1, Content.size(), f);
    fclose(f);

    // Count trailing zeroes in Content
    size_t trailingZeroes = 0;
    for (size_t i = Content.size(); (i > (Content.size()) - 0x18) && Content[i - 1] == 0; --i) {
        ++trailingZeroes;
    }

    // remove at least 0x18 trailing zeroes
    // Add padding so file size is divided by 8.
    // After that add 0x10 zero bytes at the end, so encrypted block does not contain elf data
    size_t origSize = Content.size();
    size_t newSize  = ((origSize - trailingZeroes) / 8 + 3) * 8; // Divide by 8, add 3 blocks, and multiply by 8
    Content.resize(newSize, 0);

    // TODO: encrypted Kbit hold some useful data
    static uint8_t *USER_Kbit;
    switch (headerid) {
        case HEADER::FMCB:
        case HEADER::DNASLOAD:
            USER_Kbit = USER_Kbit_FMCB;
            break;
        case HEADER::FHDB:
            USER_Kbit = USER_Kbit_FHDB;
            break;
        case HEADER::MBR:
            USER_Kbit = USER_Kbit_MBR;
            break;
        default:
            printf("WARNING: unknown header ID (%d) defaulting to FHDB ID\n", headerid);
            USER_Kbit = USER_Kbit_FHDB;
            break;
    }

    Kbit.resize(16);
    memcpy(Kbit.data(), USER_Kbit, 16);
    // std::fill(Kbit.data(), Kbit.data() + 16, 0x00);

    // TODO: encrypted Kc hold some useful data
    Kc.resize(16);
    // memcpy(Kbit.data(), USER_Kc_MBR, 16);
    std::fill(Kc.data(), Kc.data() + 16, 0x00);

    // arcade
    if (ks.GetOverrideKbit().size() && ks.GetOverrideKc().size()) {
        printf("-- Kbit and Kc overriden by Keystore!\n");
        memcpy(Kbit.data(), ks.GetOverrideKbit().data(), 16);
        memcpy(Kc.data(), ks.GetOverrideKc().data(), 16);
    }

    std::fill(bitTable.gap, bitTable.gap + 3, 0);

    // You can create your own sets of files
    // at least 2 blocks, seems at least 1 block should be signed

    // TODO: fix BIT_BLOCK_SIGNED only code as signed only is faster

    // BlockCount - will be number of blocks (0-255)
    // Blocks[i].Flags can be any combination of BIT_BLOCK_SIGNED and BIT_BLOCK_ENCRYPTED flags (4 different sets)
    // Blocks[i].Size - block size, should be division of 8 if BIT_BLOCK_ENCRYPTED is set

    // This is old kelftool block set
    // bitTable.BlockCount      = 2;
    // bitTable.Blocks[0].Size  = 0x20;
    // bitTable.Blocks[0].Flags = BIT_BLOCK_SIGNED | BIT_BLOCK_ENCRYPTED;
    // bitTable.Blocks[1].Size  = Content.size() - bitTable.Blocks[0].Size;
    // bitTable.Blocks[1].Flags = 0;

    // we add 0x10 zero bytes to the end of elf file, so we encrypt them and still be able to see the main part of elf unencrypted
    bitTable.BlockCount      = 2;
    bitTable.Blocks[1].Size  = 0x10;
    bitTable.Blocks[1].Flags = BIT_BLOCK_SIGNED | BIT_BLOCK_ENCRYPTED;
    bitTable.Blocks[0].Size  = Content.size() - bitTable.Blocks[1].Size;
    bitTable.Blocks[0].Flags = 0;

    // bitTable.BlockCount      = 1;
    // bitTable.Blocks[0].Size  = 0x20;
    // bitTable.Blocks[0].Flags = BIT_BLOCK_SIGNED;

    // bitTable.BlockCount      = 6;
    // bitTable.Blocks[0].Size  = 0x40;
    // bitTable.Blocks[0].Flags = 2;
    // bitTable.Blocks[1].Size  = 0x10;
    // bitTable.Blocks[1].Flags = BIT_BLOCK_SIGNED | BIT_BLOCK_ENCRYPTED;
    // bitTable.Blocks[2].Size  = 0x100;
    // bitTable.Blocks[2].Flags = BIT_BLOCK_ENCRYPTED;
    // bitTable.Blocks[3].Size  = 0x40;
    // bitTable.Blocks[3].Flags = 0;
    // bitTable.Blocks[4].Size  = 0x10;
    // bitTable.Blocks[4].Flags = BIT_BLOCK_SIGNED;
    // bitTable.Blocks[5].Size  = 0x100;
    // bitTable.Blocks[5].Flags = BIT_BLOCK_ENCRYPTED;

    uint32_t offset = 0;
    for (int i = 0; i < bitTable.BlockCount; ++i) {
        // ignore last block defined size, and just use the rest of elf
        // the same if current block reaches end of file
        if ((i == bitTable.BlockCount - 1) || (offset + bitTable.Blocks[i].Size > Content.size())) {
            bitTable.Blocks[i].Size = Content.size() - offset;
            bitTable.BlockCount     = i + 1;
            // TODO: zero padding last block, 0x8 bytes if signed, 0x10 bytes if encrypted
        }

        memset(bitTable.Blocks[i].Signature, 0, 8);

        // Sign
        if (bitTable.Blocks[i].Flags & BIT_BLOCK_SIGNED) {
            if (!(bitTable.Blocks[i].Flags & BIT_BLOCK_ENCRYPTED)) {
                // TODO: fix BIT_BLOCK_SIGNED alone support
                // TODO: implement 1DES/3DES difference
                printf("bitTable.Blocks[%d].Flags = BIT_BLOCK_SIGNED is not implemented during encryption. Encryption aborted.\n", i);
                fclose(f);
                return KELF_ERROR_UNSUPPORTED_FILE;
            }
            if (bitTable.Blocks[i].Size % 0x8) {
                printf("bitTable.Blocks[%d].Size = %08X is not bounded to 0x8 (BIT_BLOCK_SIGNED). Encryption aborted.\n", i, bitTable.Blocks[i].Size);
                fclose(f);
                return KELF_ERROR_UNSUPPORTED_FILE;
            }
            for (unsigned int j = 0; j < bitTable.Blocks[i].Size; j += 8)
                xor_bit(&Content.data()[offset + j], bitTable.Blocks[i].Signature, bitTable.Blocks[i].Signature, 8);

            uint8_t MG_SIG_MASTER_AND_HASH_KEY[16];
            memcpy(MG_SIG_MASTER_AND_HASH_KEY, ks.GetSignatureMasterKey().data(), 8);
            memcpy(MG_SIG_MASTER_AND_HASH_KEY + 8, ks.GetSignatureHashKey().data(), 8);

            TdesCbcCfb64Encrypt(bitTable.Blocks[i].Signature, bitTable.Blocks[i].Signature, 8, MG_SIG_MASTER_AND_HASH_KEY, 2, MG_IV_NULL);
        }

        // Encrypt
        if (bitTable.Blocks[i].Flags & BIT_BLOCK_ENCRYPTED) {
            if (bitTable.Blocks[i].Size % 0x10) {
                printf("bitTable.Blocks[%d].Size = %08X is not bounded to 0x10 (BIT_BLOCK_ENCRYPTED). Encryption aborted.\n", i, bitTable.Blocks[i].Size);
                fclose(f);
                return KELF_ERROR_UNSUPPORTED_FILE;
            }
            TdesCbcCfb64Encrypt(&Content.data()[offset], &Content.data()[offset], bitTable.Blocks[i].Size, Kc.data(), 2, ks.GetContentIV().data());
        }

        // if we reach the end of file
        offset += bitTable.Blocks[i].Size;
    }

    bitTable.HeaderSize = sizeof(KELFHeader) + 8 + 16 + 16 + (bitTable.BlockCount * 2 + 1) * 8 + 8 + 8; // header + header signature + kbit + kc + bittable (2 blocks) + bittable signature + root signature
    return 0;
}

int Kelf::SaveContent(const std::string &filename)
{
    FILE *f = fopen(filename.c_str(), "wb");
    if (f == NULL) {
        fprintf(stderr, "Couldn't open %s: %s\n", filename.c_str(), strerror(errno));
        return KELF_ERROR_UNSUPPORTED_FILE;
    }
    fwrite(Content.data(), 1, Content.size(), f);
    fclose(f);

    return 0;
}

std::string Kelf::GetHeaderSignature(KELFHeader &header)
{
    uint8_t HMasterEnc[sizeof(KELFHeader)];
    TdesCbcCfb64Encrypt(HMasterEnc, (uint8_t *)&header, sizeof(KELFHeader), ks.GetSignatureMasterKey().data(), 1, MG_IV_NULL);

    uint8_t Hsign[8];
    memcpy(Hsign, HMasterEnc + sizeof(HMasterEnc) - 8, 8);
    TdesCbcCfb64Decrypt(Hsign, Hsign, 8, ks.GetSignatureHashKey().data(), 1, MG_IV_NULL);
    TdesCbcCfb64Encrypt(Hsign, Hsign, 8, ks.GetSignatureMasterKey().data(), 1, MG_IV_NULL);

    return std::string((char *)Hsign, 8);
}

std::string Kelf::DeriveKeyEncryptionKey(KELFHeader &header)
{
    uint8_t *KelfHeader = (uint8_t *)&header;
    uint8_t HeaderData[8];
    xor_bit(KelfHeader, &KelfHeader[8], HeaderData, 8);

    uint8_t KEK[16];
    xor_bit(ks.GetKbitIV().data(), HeaderData, KEK, 8);
    xor_bit(ks.GetKcIV().data(), HeaderData, &KEK[8], 8);

    TdesCbcCfb64Encrypt(KEK, KEK, 8, ks.GetKbitMasterKey().data(), 2, MG_IV_NULL);
    TdesCbcCfb64Encrypt(&KEK[8], &KEK[8], 8, ks.GetKcMasterKey().data(), 2, MG_IV_NULL);

    return std::string((char *)KEK, 16);
}

void Kelf::DecryptKeys(const std::string &KEK)
{
    TdesCbcCfb64Decrypt((uint8_t *)Kbit.data(), (uint8_t *)Kbit.data(), 8, (uint8_t *)KEK.data(), 2, MG_IV_NULL);
    TdesCbcCfb64Decrypt((uint8_t *)Kbit.data() + 8, (uint8_t *)Kbit.data() + 8, 8, (uint8_t *)KEK.data(), 2, MG_IV_NULL);

    TdesCbcCfb64Decrypt((uint8_t *)Kc.data(), (uint8_t *)Kc.data(), 8, (uint8_t *)KEK.data(), 2, MG_IV_NULL);
    TdesCbcCfb64Decrypt((uint8_t *)Kc.data() + 8, (uint8_t *)Kc.data() + 8, 8, (uint8_t *)KEK.data(), 2, MG_IV_NULL);
}

void Kelf::EncryptKeys(const std::string &KEK)
{
    TdesCbcCfb64Encrypt((uint8_t *)Kbit.data(), (uint8_t *)Kbit.data(), 8, (uint8_t *)KEK.data(), 2, MG_IV_NULL);
    TdesCbcCfb64Encrypt((uint8_t *)Kbit.data() + 8, (uint8_t *)Kbit.data() + 8, 8, (uint8_t *)KEK.data(), 2, MG_IV_NULL);

    TdesCbcCfb64Encrypt((uint8_t *)Kc.data(), (uint8_t *)Kc.data(), 8, (uint8_t *)KEK.data(), 2, MG_IV_NULL);
    TdesCbcCfb64Encrypt((uint8_t *)Kc.data() + 8, (uint8_t *)Kc.data() + 8, 8, (uint8_t *)KEK.data(), 2, MG_IV_NULL);
}

std::string Kelf::GetBitTableSignature()
{
    uint8_t hash[8];
    memcpy(hash, &Kbit[0], 8);
    if (memcmp(&Kbit[0], &Kbit[8], 8) != 0)
        xor_bit(&Kbit[8], hash, hash, 8);

    xor_bit(&Kc[0], hash, hash, 8);
    if (memcmp(&Kc[0], &Kc[8], 8) != 0)
        xor_bit(&Kc[8], hash, hash, 8);

    for (int i = 0; i < bitTable.BlockCount * 2 + 1; i++)
        xor_bit(&((uint8_t *)&bitTable)[i * 8], hash, hash, 8);

    uint8_t MG_SIG_MASTER_AND_HASH_KEY[16];
    memcpy(MG_SIG_MASTER_AND_HASH_KEY, ks.GetSignatureMasterKey().data(), 8);
    memcpy(MG_SIG_MASTER_AND_HASH_KEY + 8, ks.GetSignatureHashKey().data(), 8);

    uint8_t signature[8];
    TdesCbcCfb64Encrypt(signature, hash, 8, MG_SIG_MASTER_AND_HASH_KEY, 2, MG_IV_NULL);

    return std::string((char *)signature, 8);
}

std::string Kelf::GetRootSignature(const std::string &HeaderSignature, const std::string &BitTableSignature)
{
    std::string Signatures;
    Signatures += HeaderSignature;
    Signatures += BitTableSignature;

    for (int i = 0; i < bitTable.BlockCount; i++)
        if (bitTable.Blocks[i].Flags & BIT_BLOCK_SIGNED)
            Signatures += std::string((char *)bitTable.Blocks[i].Signature, 8);

    TdesCbcCfb64Encrypt((uint8_t *)Signatures.data(), (uint8_t *)Signatures.data(), Signatures.size(), ks.GetRootSignatureMasterKey().data(), 1, MG_IV_NULL);
    std::string Root;
    Root.resize(8);
    TdesCbcCfb64Decrypt((uint8_t *)Root.data(), (uint8_t *)Signatures.substr(Signatures.size() - 8).data(), 8, ks.GetRootSignatureHashKey().data(), 2, MG_IV_NULL);

    return Root;
}

void Kelf::DecryptContent(int keycount)
{
    uint32_t offset = 0;
    for (int i = 0; i < bitTable.BlockCount; i++) {
        if (bitTable.Blocks[i].Flags & BIT_BLOCK_ENCRYPTED)
            TdesCbcCfb64Decrypt(&Content.data()[offset], &Content.data()[offset], bitTable.Blocks[i].Size, Kc.data(), keycount, ks.GetContentIV().data());
        offset += bitTable.Blocks[i].Size;
    }
}

int Kelf::VerifyContentSignature()
{
    uint32_t offset = 0;
    for (unsigned int i = 0; i < bitTable.BlockCount; i++) {
        if (bitTable.Blocks[i].Flags & BIT_BLOCK_SIGNED) {
            uint8_t signature[8];
            memset(signature, 0, 8);

            if (bitTable.Blocks[i].Flags & BIT_BLOCK_ENCRYPTED) {
                for (unsigned int j = 0; j < bitTable.Blocks[i].Size; j += 8)
                    xor_bit(&Content.data()[offset + j], signature, signature, 8);

                uint8_t MG_SIG_MASTER_AND_HASH_KEY[16];
                memcpy(MG_SIG_MASTER_AND_HASH_KEY, ks.GetSignatureMasterKey().data(), 8);
                memcpy(MG_SIG_MASTER_AND_HASH_KEY + 8, ks.GetSignatureHashKey().data(), 8);

                TdesCbcCfb64Encrypt(signature, signature, 8, MG_SIG_MASTER_AND_HASH_KEY, 2, MG_IV_NULL);
            } else {
                std::string SigMasterEnc;
                SigMasterEnc.resize(bitTable.Blocks[i].Size);
                TdesCbcCfb64Encrypt(SigMasterEnc.data(), &Content.data()[offset], bitTable.Blocks[i].Size, ks.GetSignatureMasterKey().data(), 1, MG_IV_NULL);
                // printf("SigMasterEnc.data() = ");
                // for (unsigned int j = 0; j < 8; ++j)
                //     printf(" %02X", (unsigned char)SigMasterEnc.data()[j]);
                // printf("\n");

                memcpy(signature, &SigMasterEnc.data()[bitTable.Blocks[i].Size - 8], 8);
                // printf("signature = ");
                // for (unsigned int j = 0; j < 8; ++j)
                //     printf(" %02X", (unsigned char)signature[j]);
                // printf("\n");

                TdesCbcCfb64Decrypt(signature, signature, 8, ks.GetSignatureHashKey().data(), 1, MG_IV_NULL);
                // printf("signature = ");
                // for (unsigned int j = 0; j < 8; ++j)
                //     printf(" %02X", (unsigned char)signature[j]);
                // printf("\n");

                TdesCbcCfb64Encrypt(signature, signature, 8, ks.GetSignatureMasterKey().data(), 1, MG_IV_NULL);
                printf("signature = ");
                for (unsigned int j = 0; j < 8; ++j)
                    printf(" %02X", (unsigned char)signature[j]);
                printf("\n");
            }

            if (memcmp(bitTable.Blocks[i].Signature, signature, 8) != 0) {
                printf("bitTable.Blocks[%u].Signature = ", i);
                for (unsigned int j = 0; j < 8; ++j)
                    printf(" %02X", (unsigned char)bitTable.Blocks[i].Signature[j]);
                printf("\n");
                printf("Signature calculated         = ");
                for (unsigned int j = 0; j < 8; ++j)
                    printf(" %02X", (unsigned char)signature[j]);
                printf("\n");
                return KELF_ERROR_INVALID_CONTENT_SIGNATURE;
            }
        }

        offset += bitTable.Blocks[i].Size;
    }

    return 0;
}
